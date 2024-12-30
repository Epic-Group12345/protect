import os
import json
import time
import glob
import hashlib
import asyncio
import aiohttp
import docker
from pathlib import Path

# Configuration is loaded from a local JSON file
with open('config.json', 'r') as f:
    config = json.load(f)

VOLUMES_DIR = config.get('volumes_dir', '/var/lib/pterodactyl/volumes')
STRATEGIES_DIR = Path(__file__).resolve().parent / 'strategies'
PUBLIC_WEBHOOK_URL = config.get('public_whook')
PRIVATE_WEBHOOK_URL = config.get('private_whook')
PTERODACTYL_API_URL = config.get('panel') + "/api/application"
PTERODACTYL_API_KEY = config.get('key')

docker_client = docker.from_env()

# Load flagged containers to avoid redundant checks
if os.path.exists('flagged.json'):
    with open('flagged.json', 'r') as f:
        flagged_containers = json.load(f)
else:
    flagged_containers = {}

# Calculate SHA256 hash for a given file
async def calculate_file_hash(file_path):
    hash_sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    except Exception as e:
        print(f"Error calculating hash for {file_path}: {e}")
        return None

# Get the Pterodactyl server ID associated with a given UUID
async def get_server_id_from_uuid(uuid):
    headers = {
        'Accept': "application/json",
        'Content-Type': "application/json",
        'Authorization': f"Bearer {PTERODACTYL_API_KEY}"
    }
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(f"{PTERODACTYL_API_URL}/servers?per_page=50000", headers=headers) as resp:
                data = await resp.json()
                for server in data.get('data', []):
                    if server['attributes']['uuid'] == uuid:
                        return server['attributes']['id']
            return None
        except Exception as e:
            print(f"Error fetching server data: {e}")
            return None

# Suspend server via Pterodactyl API
async def suspend_server(server_id):
    headers = {
        'Accept': "application/json",
        'Content-Type': "application/json",
        'Authorization': f"Bearer {PTERODACTYL_API_KEY}"
    }
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(f"{PTERODACTYL_API_URL}/servers/{server_id}/suspend", headers=headers) as resp:
                if resp.status == 204:
                    print(f"Server {server_id} successfully suspended.")
                else:
                    print(f"Failed to suspend server {server_id}. Status code: {resp.status}")
        except Exception as e:
            print(f"Error suspending server {server_id}: {e}")

# Send public alert via webhook
async def send_public_alert(uuid, server_id):
    embed = {
        'title': "Suspicious activity detected using Protect.",
        'color': 0x5046e4,
        'fields': [
            {
                'name': 'Container',
                'value': server_id or "Unknown",
                'inline': False
            }
        ],
        'timestamp': time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        'footer': {'text': "Powered by Protect"}
    }
    payload = {'embeds': [embed]}
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(PUBLIC_WEBHOOK_URL, json=payload) as resp:
                if resp.status == 204 or resp.status == 200:
                    print(f"Public alert for container {uuid} sent")
                else:
                    print(f"Failed to send public alert for container {uuid}. Status code: {resp.status}")
        except Exception as e:
            print(f"Error sending public alert for container {uuid}: {e}")

# Send detailed private alert via webhook
async def send_private_alert(uuid, server_id, flags):
    embed = {
        'title': f"Incident [{server_id}]",
        'color': 0x5046e4,
        'fields': [
            {
                'name': "Docker UUID",
                'value': uuid,
                'inline': True
            },
            {
                'name': "Panel Server ID",
                'value': server_id or "Unknown",
                'inline': True
            },
            {
                'name': "All Flags",
                'value': "\n".join(flags)
            }
        ],
        'footer': {'text': "Powered by Protect"},
        'timestamp': time.strftime("%Y-%m-%dT%H:%M:%SZ")
    }
    payload = {'embeds': [embed]}
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(PRIVATE_WEBHOOK_URL, json=payload) as resp:
                if resp.status == 204 or resp.status == 200:
                    print(f"Private alert for container {uuid} sent")
                else:
                    print(f"Failed to send private alert for container {uuid}. Status code: {resp.status}")
        except Exception as e:
            print(f"Error sending private alert for container {uuid}: {e}")

# Load detection strategies from .protect files
async def load_strategies():
    strategies = []
    try:
        for file_path in STRATEGIES_DIR.glob('*.protect'):
            try:
                with open(file_path, 'r') as f:
                    strategy = json.load(f)
                    if not strategy.get('name') or not strategy.get('type') or not isinstance(strategy.get('checks'), list):
                        print(f"Invalid strategy structure in file {file_path.name}. Skipping.")
                        continue
                    strategies.append(strategy)
                    print(f"Loaded strategy: {strategy['name']} from {file_path.name}")
            except Exception as e:
                print(f"Error loading strategy from {file_path.name}: {e}")
    except Exception as e:
        print(f"Error reading strategies directory: {e}")

    if not strategies:
        print("No valid strategies loaded. Check your .protect files and permissions.")
    else:
        print(f"Successfully loaded {len(strategies)} strategies.")

    return strategies

# Execute a given strategy on a Docker volume
async def execute_strategy(strategy, volume_path, container):
    flags = []
    print(f"Executing strategy: {strategy['name']} for volume {volume_path}")
    if not isinstance(strategy.get('checks'), list):
        print(f"Invalid checks array in strategy {strategy['name']} for volume {volume_path}")
        return flags

    for check_config in strategy['checks']:
        if not check_config or not isinstance(check_config, dict) or not check_config.get('type'):
            print(f"Invalid check configuration in strategy {strategy['name']} for volume {volume_path}")
            continue

        flag_raised = False
        message_template = check_config.get('message', "An undefined issue was detected")
        try:
            print(f"Performing check type: {check_config['type']} for strategy {strategy['name']} on volume {volume_path}")
            if check_config['type'] in ['file_existence', 'file_content', 'file_size']:
                flag_data = await file_check(volume_path, check_config)
            elif check_config['type'] == 'dependency':
                flag_data = await dependency_check(volume_path, check_config)
            elif check_config['type'] == 'log_content':
                flag_data = await log_content_check(container, check_config)
            elif check_config['type'] == 'process_check':
                flag_data = await process_check(container, check_config)
            elif check_config['type'] == 'network_usage':
                flag_data = await network_usage_check(container, check_config)
            else:
                print(f"Unknown check type: {check_config['type']} in strategy {strategy['name']} for volume {volume_path}")
                continue

            if flag_data:
                message = replace_placeholders(message_template, flag_data)
                flags.append(message)
                print(f"Flag raised: {message}")

        except Exception as e:
            print(f"Error executing check {check_config['type']} in strategy {strategy['name']} for volume {volume_path}: {e}")

    return flags

# Replace placeholders in messages with actual data
def replace_placeholders(template, data):
    return template.format(
        pattern=data.get('pattern', ''),
        filename=data.get('filename', ''),
        dependency=data.get('dependency', ''),
        usage=f"{data.get('usage', 0) / 1024 / 1024:.2f}",
        processes=', '.join(data.get('processes', []))
    )

# File checks
async def file_check(volume_path, check_config):
    if not check_config.get('path'):
        print(f"Path not defined for check {check_config['type']} in volume {volume_path}")
        return False

    target_path = os.path.join(volume_path, check_config['path'])

    if check_config['type'] == 'file_existence':
        return await file_existence_check(target_path, check_config)
    elif check_config['type'] == 'file_content':
        return await file_content_check(target_path, check_config)
    elif check_config['type'] == 'file_size':
        return await file_size_check(target_path, check_config)
    else:
        raise ValueError(f"Invalid file check type: {check_config['type']}")

# Check for the existence of files matching patterns
async def file_existence_check(target_path, check_config):
    patterns = check_config.get('patterns', [])
    for pattern in patterns:
        full_pattern = os.path.join(target_path, pattern)
        matches = glob.glob(full_pattern)
        if matches:
            return {'filename': os.path.basename(matches[0])}
    return False

# Check if file content matches any of the patterns
async def file_content_check(target_path, check_config):
    patterns = check_config.get('patterns', [])
    if os.path.exists(target_path):
        with open(target_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            for pattern in patterns:
                if pattern in content:
                    return {'pattern': pattern}
    return False

# Check if file size exceeds the maximum size
async def file_size_check(target_path, check_config):
    max_size = check_config.get('max_size', 0)
    if os.path.exists(target_path):
        size = os.path.getsize(target_path)
        if size > max_size:
            return {'filename': os.path.basename(target_path)}
    return False

# Check for malicious or unauthorized dependencies
async def dependency_check(volume_path, check_config):
    file_name = check_config.get('file', 'package.json')
    patterns = check_config.get('patterns', [])
    package_file = os.path.join(volume_path, file_name)
    if os.path.exists(package_file):
        try:
            with open(package_file, 'r') as f:
                package_data = json.load(f)
            dependencies = package_data.get('dependencies', {})
            dependencies.update(package_data.get('devDependencies', {}))
            for pattern in patterns:
                for dep_name in dependencies.keys():
                    if pattern.lower() in dep_name.lower():
                        return {'dependency': dep_name}
        except Exception as e:
            print(f"Error parsing {file_name} in {package_file}: {e}")
    else:
        print(f"{file_name} not found in {package_file}")
    return False

# Check container logs for patterns
async def log_content_check(container, check_config):
    patterns = check_config.get('patterns', [])
    try:
        logs = container.logs(tail=1000).decode('utf-8')
        for pattern in patterns:
            if pattern.lower() in logs.lower():
                return {'pattern': pattern}
    except Exception as e:
        print(f"Error checking container logs: {e}")
    return False

# Check for processes consuming more CPU than the specified threshold
async def process_check(container, check_config):
    cmd = check_config.get('command')
    cpu_threshold = check_config.get('cpu_threshold', 0)
    try:
        exec_instance = container.exec_run(cmd, stdout=True, stderr=True)
        output = exec_instance.output.decode('utf-8')
        high_cpu_processes = []
        for line in output.strip().split('\n'):
            parts = line.strip().split()
            if len(parts) > 8:
                try:
                    cpu_usage = float(parts[8])
                    if cpu_usage > cpu_threshold:
                        high_cpu_processes.append(line.strip())
                except ValueError:
                    continue
        if high_cpu_processes:
            return {'processes': high_cpu_processes}
    except Exception as e:
        print(f"Error checking container processes: {e}")
    return False

# Check if container network usage exceeds the specified threshold
async def network_usage_check(container, check_config):
    threshold = check_config.get('threshold', 0)
    try:
        stats = container.stats(stream=False)
        networks = stats.get('networks', {})
        total_usage = sum(net.get('rx_bytes', 0) + net.get('tx_bytes', 0) for net in networks.values())
        if total_usage > threshold:
            return {'usage': total_usage}
    except Exception as e:
        print(f"Error checking container network usage: {e}")
    return False

# Apply strategies to a given Docker volume
async def check_volume(uuid, strategies):
    volume_path = os.path.join(VOLUMES_DIR, uuid)
    flags = []
    if not os.path.exists(volume_path):
        print(f"Volume directory for {uuid} does not exist. Skipping...")
        return flags

    try:
        container = docker_client.containers.get(uuid)
    except docker.errors.NotFound:
        print(f"Container {uuid} not found. Skipping...")
        return flags
    except Exception as e:
        print(f"Error accessing container {uuid}: {e}")
        return flags

    for strategy in strategies:
        strategy_flags = await execute_strategy(strategy, volume_path, container)
        flags.extend(strategy_flags)

    return flags

# Scan all Docker containers/volumes
async def scan_all_containers(strategies):
    for uuid in os.listdir(VOLUMES_DIR):
        if flagged_containers.get(uuid):
            print(f"Container {uuid} is already flagged. Skipping...")
            continue
        try:
            flags = await check_volume(uuid, strategies)
            if flags:
                server_id = await get_server_id_from_uuid(uuid)
                if server_id:
                    await suspend_server(server_id)
                await send_public_alert(uuid, server_id)
                await send_private_alert(uuid, server_id, flags)
                flagged_containers[uuid] = True
                with open('flagged.json', 'w') as f:
                    json.dump(flagged_containers, f)
        except Exception as e:
            print(f"Error processing volume {uuid}: {e}")

# Main loop for continuous scanning
async def main():
    print("Starting continuous container abuse detection...")
    strategies = await load_strategies()
    while True:
        try:
            await scan_all_containers(strategies)
            print("Scanning completed. Waiting 180 seconds before next scan...")
        except Exception as e:
            print(f"Error in scanning loop: {e}")
        finally:
            await asyncio.sleep(180)  # Wait 3 minutes before next scan

if __name__ == "__main__":
    asyncio.run(main())