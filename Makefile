deploy: setup-bridge build-rust build-images deploy-clab

destroy: destroy-clab remove-bridge

build-rust:
	cargo xtask build-ebpf --release
	cargo build --release

build-images: build-lb-image build-backend-image

build-lb-image:
	docker image build -t lb:local . -f ./test/Dockerfile --target lb

build-backend-image:
	docker image build -t back:local . -f ./test/Dockerfile --target backend

deploy-clab: 
	sudo containerlab deploy --topo ./test/topology.yaml

destroy-clab:
	sudo containerlab destroy --topo ./test/topology.yaml

setup-bridge:
	sudo ip link add name aya-br0 type bridge
	sudo ip link set aya-br0 up

remove-bridge:
	sudo ip link del aya-br0

clean: destroy

mrproper:
	rm -Rf ./clab-aya-lb-dr
	docker image rm lb:local || true
	docker image rm back:local || true

	
