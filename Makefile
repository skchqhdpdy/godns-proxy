#!/usr/bin/env make

# 인자 처리 로직: 첫 번째 인자가 'drop' 또는 'undrop'일 경우 두 번째 인자를 IP로 취급
ifeq ($(firstword $(MAKECMDGOALS)),$(filter $(firstword $(MAKECMDGOALS)),drop undrop))
  # 두 번째 단어를 IP로 추출
  DROP_IP := $(word 2, $(MAKECMDGOALS))
  # IP 부분을 make가 타겟으로 오해하지 않도록 빈 타겟으로 정의
  $(eval $(DROP_IP):;@:)
endif

build:
	docker build -t godns:latest .

run:
	docker compose up godns

run-bg:
	docker compose up -d godns

restart:
	docker compose down godns && docker compose up -d godns && make logs

stop:
	docker compose down

last?=1000
logs:
	docker compose logs -f godns --tail ${last}

# IP 차단 명령어 (컨테이너 내부 실행)
drop:
	@if [ -z "$(DROP_IP)" ]; then echo "사용법: make drop <IP>"; exit 1; fi
	@echo "차단 중: $(DROP_IP)..."
	docker compose exec -u root godns iptables -I INPUT -s $(DROP_IP) -j DROP
	@echo "성공: 컨테이너 내부에서 $(DROP_IP)가 차단되었습니다."

# IP 차단 해제
undrop:
	@if [ -z "$(DROP_IP)" ]; then echo "사용법: make undrop <IP>"; exit 1; fi
	@echo "차단 해제 중: $(DROP_IP)..."
	docker compose exec -u root godns iptables -D INPUT -s $(DROP_IP) -j DROP
	@echo "성공: $(DROP_IP) 차단이 해제되었습니다."
list-drop:
	docker compose exec -u root godns iptables -L INPUT -n --line-numbers
