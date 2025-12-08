# sideload_server.py - expanded for gNB validation
from flask import Flask, jsonify, request
import subprocess
import time
import re

app = Flask(__name__)

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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
