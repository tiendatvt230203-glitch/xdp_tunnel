#!/bin/bash

install_deps() {
    apt-get update
    apt-get install -y clang llvm libelf-dev libbpf-dev linux-headers-$(uname -r) gcc make
}

build() {
    cd "$(dirname "$0")"
    make clean
    make
}

run() {
    if [ -z "$1" ]; then
        echo "Usage: $0 run <config_file>"
        exit 1
    fi
    cd "$(dirname "$0")"
    ./loader "$1"
}

stop() {
    pkill -f loader
}

case "$1" in
    install)
        install_deps
        ;;
    build)
        build
        ;;
    run)
        run "$2"
        ;;
    stop)
        stop
        ;;
    *)
        echo "Usage: $0 {install|build|run <config>|stop}"
        exit 1
        ;;
esac
