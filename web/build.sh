
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$SCRIPT_DIR/build"
OPENSSL_VERSION="3.3.2"
OPENSSL_DIR="$BUILD_DIR/openssl-$OPENSSL_VERSION"
OPENSSL_INSTALL="$BUILD_DIR/openssl-install"

mkdir -p "$BUILD_DIR"


if [ ! -f "$OPENSSL_INSTALL/lib/libcrypto.a" ]; then
    cd "$BUILD_DIR"
    if [ ! -d "$OPENSSL_DIR" ]; then
        curl -L "https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/openssl-$OPENSSL_VERSION.tar.gz" -o openssl.tar.gz
        tar xzf openssl.tar.gz
        rm openssl.tar.gz
    fi

    echo "buildig openssl"
    cd "$OPENSSL_DIR"

    
    [ -f Makefile ] && emmake make clean 2>/dev/null || true

    
    CC=emcc AR=emar RANLIB=emranlib ./Configure \
        linux-generic32 \
        no-asm \
        no-threads \
        no-engine \
        no-dso \
        no-shared \
        no-sock \
        no-afalgeng \
        no-tests \
        no-ui-console \
        --prefix="$OPENSSL_INSTALL" \
        --openssldir="$OPENSSL_INSTALL" \
        -static \
        -O2 \
        -DOPENSSL_NO_SECURE_MEMORY \
        -DNO_SYSLOG \
        -DOPENSSL_NO_DGRAM \
        -DOPENSSL_NO_SOCK

    
    make -j$(nproc) build_libs CC=emcc AR=emar RANLIB=emranlib
    make install_dev CC=emcc AR=emar RANLIB=emranlib

    echo "openssl done"
else
    echo "ok"
fi


echo compiling

SOURCES=(
    "$PROJECT_DIR/src/trident.c"
    "$PROJECT_DIR/hash/blake.c"
    "$PROJECT_DIR/hash/sha.c"
    "$PROJECT_DIR/hash/shat.c"
    "$PROJECT_DIR/hash/wp.c"
    "$PROJECT_DIR/hash/composite.c"
    "$SCRIPT_DIR/wstr.c"
)

emcc "${SOURCES[@]}" \
    -I"$PROJECT_DIR/include" \
    -I"$PROJECT_DIR/hash" \
    -I"$OPENSSL_INSTALL/include" \
    -L"$OPENSSL_INSTALL/lib" \
    -L"$OPENSSL_INSTALL/lib64" \
    -lcrypto \
    -O2 \
    -s WASM=1 \
    -s ALLOW_MEMORY_GROWTH=1 \
    -s INITIAL_MEMORY=67108864 \
    -s MAXIMUM_MEMORY=536870912 \
    -s STACK_SIZE=1048576 \
    -s EXPORTED_FUNCTIONS='["_trident_keygen","_trident_encrypt","_trident_decrypt","_wasm_malloc","_wasm_free","_get_mkeysize","_get_blocksize","_malloc","_free"]' \
    -s EXPORTED_RUNTIME_METHODS='["ccall","cwrap","HEAPU8"]' \
    -s MODULARIZE=1 \
    -s EXPORT_NAME="TridentModule" \
    -s FILESYSTEM=1 \
    -o "$SCRIPT_DIR/trident.js"

echo done
