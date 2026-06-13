cd dislocker
mkdir -p build && cd build

CMAKE_PREFIX_PATH="$(brew --prefix mbedtls@3)" \
PKG_CONFIG_PATH="/usr/local/lib/pkgconfig:$(brew --prefix mbedtls@3)/lib/pkgconfig" \
cmake .. \
  -DWITH_RUBY=OFF \
  -DCMAKE_C_FLAGS="-DFUSE_DARWIN_ENABLE_EXTENSIONS=0"

make -j$(sysctl -n hw.ncpu)