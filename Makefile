build:
	podman build -t bmw.ece.ntust.edu.tw/infidel/gnb-perf:sideload .

push:
	podman push bmw.ece.ntust.edu.tw/infidel/gnb-perf:sideload
