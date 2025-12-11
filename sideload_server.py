# sideload_server.py - expanded for gNB validation
from flask import Flask, jsonify, request
import subprocess
import socket
import os
import time
import re
import requests
import threading

app = Flask(__name__)
svc_port = os.getenv('SVC_PORT', '8080')
rapp_url = os.getenv('RAPP_URL', 'http://rapp-service:5000')
node_name = os.getenv('NODE_NAME', 'unknown')

def run_cmd(cmd):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return None
        return result.stdout.strip()
    except:
        return None

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})

@app.route('/rt_status', methods=['GET'])
def rt_status():
    """Basic RT configuration"""
    isolated = run_cmd("cat /sys/devices/system/cpu/isolated")
    online = run_cmd("cat /sys/devices/system/cpu/online")
    tuned = run_cmd("nsenter -t 1 -m -u -n -i tuned-adm active")
    throttle = run_cmd("cat /proc/sys/kernel/sched_rt_runtime_us")
    kernel = run_cmd("nsenter -t 1 -m -u -n -i uname -r")

    return jsonify({
        'isolated_cpus': isolated,
        'online_cpus': online,
        'tuned_profile': tuned.replace('Current active profile:', '').strip() if tuned else None,
        'rt_throttling_us': int(throttle) if throttle else None,
        'kernel_version': kernel
    })

@app.route('/cpu/governor', methods=['GET'])
def cpu_governor():
    """CPU frequency governor - affects P1-P5 passive tests"""
    out = run_cmd("nsenter -t 1 -m -u -n -i bash -c 'cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor | sort -u'")
    return jsonify({'governors': out.split('\n') if out else None})

@app.route('/cpu/idle_states', methods=['GET'])
def cpu_idle_states():
    """CPU idle states - critical for RT performance"""
    out = run_cmd("nsenter -t 1 -m -u -n -i bash -c 'cat /sys/devices/system/cpu/cpu0/cpuidle/state*/disable'")
    return jsonify({'idle_states_disabled': out.split('\n') if out else None})

@app.route('/irq/affinity', methods=['GET'])
def irq_affinity():
    """IRQ affinity for network interfaces - affects P3 thread pinning tests"""
    pattern = request.args.get('pattern', 'ens')
    cmd = f"nsenter -t 1 -m -u -n -i bash -c 'grep -H . /proc/irq/*/smp_affinity_list | grep {pattern}'"
    out = run_cmd(cmd)

    if not out:
        return jsonify({'irq_affinity': {}})

    affinities = {}
    for line in out.split('\n'):
        if ':' in line:
            parts = line.split(':')
            irq_num = parts[0].split('/')[3]
            cpus = parts[1]
            affinities[irq_num] = cpus

    return jsonify({'irq_affinity': affinities})

@app.route('/gnb/process', methods=['GET'])
def gnb_process():
    """Find gNB process - needed for all tests"""
    out = run_cmd("nsenter -t 1 -m -u -n -i ps aux | grep -E 'nr-softmodem|gnb' | grep -v grep")

    if not out:
        return jsonify({'found': False})

    # Parse ps output to get PID
    match = re.search(r'(\d+)', out)
    pid = match.group(1) if match else None

    return jsonify({
        'found': True,
        'pid': pid,
        'process_info': out
    })

@app.route('/gnb/affinity', methods=['POST'])
def gnb_affinity():
    """Get gNB process CPU affinity - validates P3 thread pinning"""
    data = request.json
    pid = data.get('pid')

    if not pid:
        return jsonify({'error': 'pid required'}), 400

    affinity = run_cmd(f"nsenter -t 1 -m -u -n -i taskset -cp {pid}")
    priority = run_cmd(f"nsenter -t 1 -m -u -n -i chrt -p {pid}")

    return jsonify({
        'affinity': affinity,
        'scheduling_priority': priority
    })

@app.route('/gnb/threads', methods=['POST'])
def gnb_threads():
    """List gNB threads with RT priority - validates P3"""
    data = request.json
    pid = data.get('pid')

    if not pid:
        return jsonify({'error': 'pid required'}), 400

    cmd = f"nsenter -t 1 -m -u -n -i ps -eLo tid,class,rtprio,psr,comm -p {pid}"
    out = run_cmd(cmd)

    return jsonify({'threads': out})

@app.route('/network/stats', methods=['GET'])
def network_stats():
    """Network interface statistics - for all tests"""
    iface = request.args.get('interface', 'ens1f0')

    stats = run_cmd(f"nsenter -t 1 -m -u -n -i ethtool -S {iface}")
    ring = run_cmd(f"nsenter -t 1 -m -u -n -i ethtool -g {iface}")
    offload = run_cmd(f"nsenter -t 1 -m -u -n -i ethtool -k {iface} | grep -E 'rx-checksumming|tx-checksumming|scatter-gather'")

    return jsonify({
        'statistics': stats,
        'ring_buffer': ring,
        'offload_settings': offload
    })

@app.route('/ptp/status', methods=['GET'])
def ptp_status():
    """PTP synchronization status - critical for A1 tests"""
    offset = run_cmd("nsenter -t 1 -m -u -n -i bash -c 'cat /sys/class/ptp/ptp*/offset 2>/dev/null'")
    ptp_process = run_cmd("nsenter -t 1 -m -u -n -i ps aux | grep ptp4l | grep -v grep")

    return jsonify({
        'ptp_offset': offset,
        'ptp4l_running': ptp_process is not None
    })

@app.route('/memory/hugepages', methods=['GET'])
def hugepages():
    """Hugepages configuration - affects memory tests"""
    out = run_cmd("nsenter -t 1 -m -u -n -i cat /proc/meminfo | grep -i huge")
    return jsonify({'hugepages': out})

@app.route('/stress/memory', methods=['POST'])
def stress_memory():
    """Trigger memory stress - for A3 QoS tests"""
    data = request.json
    percent = data.get('percent', 50)
    duration = data.get('duration', 60)

    cmd = f"nsenter -t 1 -m -u -n -i stress-ng --vm 4 --vm-bytes {percent}% --timeout {duration}s &"
    run_cmd(cmd)

    return jsonify({'started': True, 'percent': percent, 'duration': duration})

@app.route('/cpu/offline', methods=['POST'])
def cpu_offline():
    """Disable CPU core - for A4 tests"""
    data = request.json
    cpu_id = data.get('cpu_id')

    if cpu_id is None:
        return jsonify({'error': 'cpu_id required'}), 400

    cmd = f"nsenter -t 1 -m -u -n -i bash -c 'echo 0 > /sys/devices/system/cpu/cpu{cpu_id}/online'"
    run_cmd(cmd)

    return jsonify({'cpu_id': cpu_id, 'status': 'offline'})

@app.route('/cpu/online', methods=['POST'])
def cpu_online():
    """Enable CPU core - restore after A4 tests"""
    data = request.json
    cpu_id = data.get('cpu_id')

    if cpu_id is None:
        return jsonify({'error': 'cpu_id required'}), 400

    cmd = f"nsenter -t 1 -m -u -n -i bash -c 'echo 1 > /sys/devices/system/cpu/cpu{cpu_id}/online'"
    run_cmd(cmd)

    return jsonify({'cpu_id': cpu_id, 'status': 'online'})

@app.route('/ptp/stop', methods=['POST'])
def ptp_stop():
    """Stop PTP service - for A1 tests"""
    data = request.json
    duration = data.get('duration', 30)

    cmd = f"nsenter -t 1 -m -u -n -i bash -c 'systemctl stop ptp4l && sleep {duration} && systemctl start ptp4l' &"
    run_cmd(cmd)

    return jsonify({'stopped': True, 'duration': duration})

@app.route('/network/link_down', methods=['POST'])
def link_down():
    """Bring interface down - for A2 tests"""
    data = request.json
    iface = data.get('interface', 'ens1f0')
    duration = data.get('duration', 10)

    cmd = f"nsenter -t 1 -m -u -n -i bash -c 'ip link set {iface} down && sleep {duration} && ip link set {iface} up' &"
    run_cmd(cmd)

    return jsonify({'interface': iface, 'down_duration': duration})

@app.route('/perf/start', methods=['POST'])
def perf_start():
    """Start perf profiling"""
    data = request.json or {}
    duration = data.get('duration', 15)
    frequency = data.get('frequency', 99)

    timestamp = int(time.time())
    perf_file = f"/host-tmp/perf_{timestamp}.data"

    cmd = f"nsenter -t 1 -m -u -n -i perf record -F {frequency} -a -g -o {perf_file} sleep {duration} &"
    run_cmd(cmd)

    return jsonify({
        'timestamp': timestamp,
        'perf_file': perf_file,
        'duration': duration
    })

@app.route('/perf/flamegraph', methods=['POST'])
def perf_flamegraph():
    """Generate flamegraph"""
    data = request.json
    perf_file = data['perf_file']
    svg_file = perf_file.replace('.data', '.svg')

    cmd = f"nsenter -t 1 -m -u -n -i bash -c 'perf script -i {perf_file} | /opt/FlameGraph/stackcollapse-perf.pl | /opt/FlameGraph/flamegraph.pl > {svg_file}'"
    result = run_cmd(cmd)

    if result is None:
        return jsonify({'error': 'flamegraph generation failed'}), 500

    return jsonify({'flamegraph': svg_file})

def get_node_ip():
    """Get node IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return None

def get_all_node_ips():
    """Get all IP addresses from host"""
    cmd = "nsenter -t 1 -m -u -n -i ip -4 addr show | grep inet"
    result = run_cmd(cmd)

    if not result:
        return []

    ips = []
    for line in result.split('\n'):
        # Parse: inet 192.168.8.82/24 brd...
        match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', line)
        if match:
            ip = match.group(1)
            print(ip)
            # Skip localhost
            if ip != '127.0.0.1':
                ips.append(ip)

    return ips

def get_rt_report():
    """Collect RT configuration"""
    def run(cmd):
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            return result.stdout.strip() if result.returncode == 0 else None
        except:
            return None

    return {
        'isolated_cpus': run("cat /sys/devices/system/cpu/isolated"),
        'online_cpus': run("cat /sys/devices/system/cpu/online"),
        'tuned_profile': run("nsenter -t 1 -m -u -n -i tuned-adm active"),
        'rt_throttling_us': run("cat /proc/sys/kernel/sched_rt_runtime_us"),
        'rt_period_us': run("cat /proc/sys/kernel/sched_rt_period_us"),
        'kernel_version': run("nsenter -t 1 -m -u -n -i uname -r"),
        'cpu_governor': run("nsenter -t 1 -m -u -n -i cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"),
        'hugepages_total': run("nsenter -t 1 -m -u -n -i grep HugePages_Total /proc/meminfo"),
        'hugepages_free': run("nsenter -t 1 -m -u -n -i grep HugePages_Free /proc/meminfo"),
        'hugepagesize': run("nsenter -t 1 -m -u -n -i grep Hugepagesize /proc/meminfo")
    }

def register_with_rapp():
    """Register with rApp - send all IPs"""
    rapp_url = os.getenv('RAPP_URL', 'http://rapp-service:5000')
    node_name = os.getenv('NODE_NAME', 'unknown')

    ips = get_all_node_ips()
    if not ips:
        print("No IPs found")
        return False

    rt_report = get_rt_report()

    payload = {
        'node_name': node_name,
        'ip_addresses': ips,  # Send all IPs
        'port': svc_port,
        'rt_config': rt_report,
        'skip_validation': True
    }

    try:
        resp = requests.post(f"{rapp_url}/sideload/register", json=payload, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            instance_id = data.get('instance_id')
            validated_ip = data.get('validated_ip')
            print(f"✓ Registered: {validated_ip}:{svc_port} on {node_name}")
            print(f"  Assigned ID: {instance_id}")
            print(f"  All IPs: {', '.join(ips)}")

            with open('/tmp/instance_id', 'w') as f:
                f.write(instance_id)

            return True
        else:
            print(f"✗ Registration failed: {resp.status_code}")
            print(f"Rsponse: {resp.text}")
            return False
    except Exception as e:
        print(f"✗ Failed to register: {e}")
        return False

@app.route('/report', methods=['GET'])
def report():
    """Get fresh RT metrics - no instance_id, just node"""
    rt_report = get_rt_report()

    # Try to read assigned ID if exists
    instance_id = 'unknown'
    try:
        with open('/tmp/instance_id', 'r') as f:
            instance_id = f.read().strip()
    except:
        pass

    return jsonify({
        'timestamp': time.time(),
        'node_name': os.getenv('NODE_NAME', 'unknown'),
        'instance_id': instance_id,
        'rt_config': rt_report
    })


# SIDELOAD ACTIONS ----------------------------------
@app.route('/perf/context_switches', methods=['POST'])
def perf_context_switches():
    """Measure context switches with filters"""
    data = request.json or {}
    duration = data.get('duration', 5)
    pid = data.get('pid')
    pgrep = data.get('pgrep')
    cpu_range = data.get('cpu_range')  # e.g., "0-7"
    cpu_list = data.get('cpu_list')    # e.g., [0, 2, 4]

    # Build perf command
    cmd_parts = ["nsenter -t 1 -m -u -n -i perf stat -e context-switches"]

    # CPU filter
    if cpu_range:
        cmd_parts.append(f"-C {cpu_range}")
    elif cpu_list:
        cpu_str = ','.join(map(str, cpu_list))
        cmd_parts.append(f"-C {cpu_str}")
    else:
        cmd_parts.append("-a")  # all CPUs

    # Process filter
    if pid:
        cmd_parts.append(f"-p {pid}")
    elif pgrep:
        # Get PIDs matching pattern
        pgrep_cmd = f"nsenter -t 1 -m -u -n -i pgrep {pgrep}"
        pids = run_cmd(pgrep_cmd)
        if pids:
            pid_list = ','.join(pids.split('\n'))
            cmd_parts.append(f"-p {pid_list}")
        else:
            return jsonify({'error': f'no process found for pattern: {pgrep}'}), 404

    cmd_parts.append(f"sleep {duration} 2>&1")
    cmd = ' '.join(cmd_parts)

    result = run_cmd(cmd)

    # Parse result
    count = None
    if result:
        match = re.search(r'([\d,]+)\s+context-switches', result)
        if match:
            count = int(match.group(1).replace(',', ''))

    return jsonify({
        'duration': duration,
        'context_switches': count,
        'filter': {
            'pid': pid,
            'pgrep': pgrep,
            'cpu_range': cpu_range,
            'cpu_list': cpu_list
        },
        'raw': result
    })

@app.route('/perf/cpu_usage', methods=['POST'])
def perf_cpu_usage():
    """Measure CPU usage over time"""
    data = request.json or {}
    duration = data.get('duration', 10)
    interval = data.get('interval', 1)  # sampling interval
    pid = data.get('pid')
    pgrep = data.get('pgrep')
    per_cpu = data.get('per_cpu', False)  # report per-CPU breakdown

    # Get PID if pgrep provided
    target_pid = pid
    if pgrep and not pid:
        pgrep_cmd = f"nsenter -t 1 -m -u -n -i pgrep {pgrep}"
        pids = run_cmd(pgrep_cmd)
        if pids:
            target_pid = pids.split('\n')[0]  # first match
        else:
            return jsonify({'error': f'no process found: {pgrep}'}), 404

    # Build command
    if per_cpu:
        # mpstat for per-CPU breakdown
        cmd = f"nsenter -t 1 -m -u -n -i mpstat -P ALL {interval} {duration // interval}"
    elif target_pid:
        # pidstat for specific process
        cmd = f"nsenter -t 1 -m -u -n -i pidstat -p {target_pid} {interval} {duration // interval}"
    else:
        # mpstat for overall CPU
        cmd = f"nsenter -t 1 -m -u -n -i mpstat {interval} {duration // interval}"

    result = run_cmd(cmd)

    # Parse result
    cpu_usage = parse_cpu_output(result, per_cpu, target_pid)

    return jsonify({
        'duration': duration,
        'interval': interval,
        'cpu_usage': cpu_usage,
        'filter': {
            'pid': target_pid,
            'pgrep': pgrep,
            'per_cpu': per_cpu
        },
        'raw': result
    })

def parse_cpu_output(output, per_cpu, pid):
    """Parse mpstat/pidstat output"""
    if not output:
        return None

    lines = output.strip().split('\n')
    samples = []

    for line in lines:
        # Skip headers
        if 'CPU' in line or 'Linux' in line or 'Average' in line or not line.strip():
            continue

        parts = line.split()
        if len(parts) < 3:
            continue

        try:
            if per_cpu:
                # mpstat -P ALL: timestamp CPU %usr %nice %sys %iowait %irq %soft %steal %guest %gnice %idle
                cpu_id = parts[1]
                idle = float(parts[-1])
                usage = 100.0 - idle
                samples.append({'cpu': cpu_id, 'usage_percent': round(usage, 2)})
            elif pid:
                # pidstat: TIME AM/PM UID PID %usr %system %guest %wait %CPU CPU Command
                # parts[8] is %CPU
                usage = float(parts[8])
                samples.append({'usage_percent': round(usage, 2)})
            else:
                # mpstat: timestamp CPU %usr %nice %sys %iowait %irq %soft %steal %guest %gnice %idle
                idle = float(parts[-1])
                usage = 100.0 - idle
                samples.append({'usage_percent': round(usage, 2)})
        except:
            continue

    if not samples:
        return None

    # Calculate statistics
    if per_cpu:
        # Group by CPU
        by_cpu = {}
        for sample in samples:
            cpu = sample['cpu']
            if cpu not in by_cpu:
                by_cpu[cpu] = []
            by_cpu[cpu].append(sample['usage_percent'])

        result = {}
        for cpu, values in by_cpu.items():
            result[f"cpu{cpu}"] = {
                'avg': round(sum(values) / len(values), 2),
                'min': round(min(values), 2),
                'max': round(max(values), 2)
            }
        return result
    else:
        # Overall statistics
        values = [s['usage_percent'] for s in samples]
        return {
            'avg': round(sum(values) / len(values), 2),
            'min': round(min(values), 2),
            'max': round(max(values), 2),
            'samples': samples
        }
@app.route('/perf/offcpu', methods=['POST'])
def perf_offcpu():
    """Off-CPU flamegraph - shows blocking time"""
    data = request.json or {}
    duration = data.get('duration', 30)
    pid = data.get('pid')

    timestamp = int(time.time())
    output = f"/host-tmp/offcpu_{timestamp}"

    if pid:
        cmd = f"nsenter -t 1 -m -u -n -i /usr/share/bcc/tools/offcputime -df -p {pid} {duration} > {output}.txt"
    else:
        cmd = f"nsenter -t 1 -m -u -n -i /usr/share/bcc/tools/offcputime -df {duration} > {output}.txt"

    run_cmd(cmd)

    # Generate flamegraph
    svg_cmd = f"cat {output}.txt | /opt/FlameGraph/flamegraph.pl --color=io --title='Off-CPU Time' > {output}.svg"
    run_cmd(svg_cmd)

    return jsonify({
        'flamegraph': f"{output}.svg",
        'duration': duration
    })
@app.route('/perf/thread_cpu', methods=['POST'])
def perf_thread_cpu():
    """Per-thread CPU usage - auto-find PID"""
    data = request.json or {}
    pid = data.get('pid')
    pgrep = data.get('pgrep', 'nr-softmodem')
    duration = data.get('duration', 10)
    min_cpu = data.get('min_cpu', 1.0)

    # Auto-discover PID
    if not pid:
        pgrep_cmd = f"nsenter -t 1 -m -u -n -i pgrep {pgrep}"
        pids = run_cmd(pgrep_cmd)
        if pids:
            pid = pids.split('\n')[0]
        else:
            return jsonify({'error': f'process not found: {pgrep}'}), 404

    # Get per-thread CPU
    cmd = f"nsenter -t 1 -m -u -n -i pidstat -t -p {pid} 1 {duration}"
    result = run_cmd(cmd)

    if not result:
        return jsonify({'error': 'pidstat failed'}), 500

    # Parse threads
    # Format: TIME AM/PM UID TGID TID %usr %system %guest %wait %CPU CPU Command
    # -----------------
    threads = {}
    for line in result.split('\n'):
        if 'TID' in line or not line.strip() or 'Average' in line or 'Linux' in line:
            continue

        parts = line.split()
        if len(parts) < 11:
            continue

        try:
            # TGID is parts[2], TID is parts[3]
            tgid = parts[2]
            tid = parts[3]  # CORRECT: index 3

            # Skip aggregate lines (TID is "-")
            if tid == '-':
                continue

            cpu_pct = float(parts[8])  # CORRECT: index 8 for %CPU
            comm = parts[-1]

            if tid not in threads:
                threads[tid] = {'name': comm, 'samples': []}
            threads[tid]['samples'].append(cpu_pct)
        except:
            continue

    # Calculate stats and filter
    thread_stats = []
    for tid, data in threads.items():
        samples = data['samples']
        avg_cpu = sum(samples) / len(samples)

        # Filter low CPU threads
        if avg_cpu < min_cpu:
            continue

        thread_stats.append({
            'tid': tid,
            'name': data['name'],
            'avg_cpu': round(avg_cpu, 2),
            'max_cpu': round(max(samples), 2),
            'min_cpu': round(min(samples), 2)
        })

    # Sort by avg CPU descending
    thread_stats.sort(key=lambda x: x['avg_cpu'], reverse=True)

    return jsonify({
        'pid': pid,
        'duration': duration,
        'total_threads': len(threads),
        'active_threads': len(thread_stats),
        'threads': thread_stats,
        'raw': result
    })

@app.route('/perf/latency_histogram', methods=['POST'])
def perf_latency_histogram():
    """Scheduler latency histogram"""
    data = request.json or {}
    duration = data.get('duration', 30)

    # Use perf sched for scheduling latency
    timestamp = int(time.time())
    perf_file = f"/host-tmp/sched_{timestamp}.data"

    cmd = f"nsenter -t 1 -m -u -n -i perf sched record -o {perf_file} sleep {duration}"
    run_cmd(cmd)

    # Get latency stats
    latency_cmd = f"nsenter -t 1 -m -u -n -i perf sched latency -i {perf_file}"
    result = run_cmd(latency_cmd)

    return jsonify({
        'duration': duration,
        'perf_file': perf_file,
        'latency_stats': result
    })


@app.route('/perf/cpu_heatmap', methods=['POST'])
def perf_cpu_heatmap():
    """CPU usage time-series for heat map visualization"""
    data = request.json or {}
    duration = data.get('duration', 60)
    interval = data.get('interval', 1)

    # mpstat per-CPU over time
    cmd = f"nsenter -t 1 -m -u -n -i mpstat -P ALL {interval} {duration // interval}"
    result = run_cmd(cmd)

    # Parse into time-series format
    timeseries = []
    current_time = None

    for line in result.split('\n'):
        if not line.strip() or 'Linux' in line:
            continue

        parts = line.split()
        if len(parts) < 3:
            continue

        try:
            if 'CPU' in parts:
                continue

            timestamp = parts[0]
            cpu_id = parts[2]
            idle = float(parts[-1])
            usage = 100.0 - idle

            timeseries.append({
                'timestamp': timestamp,
                'cpu': cpu_id,
                'usage': round(usage, 2)
            })
        except:
            continue

    return jsonify({
        'duration': duration,
        'interval': interval,
        'timeseries': timeseries  # Frontend renders as heat map
    })

def register_loop():
    for attempt in range(5):
        if register_with_rapp():
            break
        print(f"Retry in 10s ({attempt + 1}/5)")
        time.sleep(10)

if __name__ == '__main__':
    import time

    registration_thread = threading.Thread(target=register_loop)
    registration_thread.start()


    app.run(host='0.0.0.0', port=svc_port, debug=True, use_reloader=False)

