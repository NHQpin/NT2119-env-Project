# OQS-Provider build with openSSl


# -----path-----

If you are not running as root you might need to use "sudo apt" instead

    sudo apt update
    sudo apt -y install git build-essential perl cmake autoconf libtool zlib1g-dev
    
    export WORKSPACE=~/quantumsafe # set this to a working dir of your choice
    export BUILD_DIR=$WORKSPACE/build # this will contain all the build artifacts
    mkdir -p $BUILD_DIR/lib64
    ln -s $BUILD_DIR/lib64 $BUILD_DIR/lib

# -----copy file-----

    cp NT2119-env-Project/openssl-openssl-3.3.1.tar.gz quantumsafe
    cp NT2119-env-Project/liboqs-0.10.1.tar.gz quantumsafe
    cp NT2119-env-Project/oqs-provider-0.6.0.tar.gz quantumsafe

# -----openssl-----

    cd $WORKSPACE
    
    tar -zxvf openssl-openssl-3.3.1.tar.gz
    cd  openssl-openssl-3.3.1
    
    ./Configure \
      --prefix=$BUILD_DIR \
      no-ssl no-tls1 no-tls1_1 no-afalgeng \
      no-shared threads -lm
    
    make -j $(nproc)
    make -j $(nproc) install_sw install_ssldirs

# -----liboqs-----

    cd $WORKSPACE

    tar -zxvf liboqs-0.10.1.tar.gz
    cd liboqs-0.10.1

    mkdir build && cd build

    cmake \
      -DCMAKE_INSTALL_PREFIX=$BUILD_DIR \
      -DBUILD_SHARED_LIBS=ON \
      -DOQS_USE_OPENSSL=OFF \
      -DCMAKE_BUILD_TYPE=Release \
      -DOQS_BUILD_ONLY_LIB=ON \
      -DOQS_DIST_BUILD=ON \
      ..

    make -j $(nproc)
    make -j $(nproc) install

# -----oqs-provider-----

    cd $WORKSPACE
    
    tar -zxvf oqs-provider-0.6.0.tar.gz
    cd oqs-provider-0.6.0
    
    liboqs_DIR=$BUILD_DIR cmake \
      -DCMAKE_INSTALL_PREFIX=$WORKSPACE/oqs-provider \
      -DOPENSSL_ROOT_DIR=$BUILD_DIR \
      -DCMAKE_BUILD_TYPE=Release \
      -S . \
      -B _build
    cmake --build _build
    
    # Manually copy the lib files into the build dir
    cp _build/lib/* $BUILD_DIR/lib/
    
    # We need to edit the openssl config to use the oqsprovider
    sed -i "s/default = default_sect/default = default_sect\noqsprovider = oqsprovider_sect/g" $BUILD_DIR/ssl/openssl.cnf &&
    sed -i "s/\[default_sect\]/\[default_sect\]\nactivate = 1\n\[oqsprovider_sect\]\nactivate = 1\n/g" $BUILD_DIR/ssl/openssl.cnf
  
# -----These env vars need to be set for the oqsprovider to be used when using OpenSSL-----

    export OPENSSL_CONF=$BUILD_DIR/ssl/openssl.cnf
    export OPENSSL_MODULES=$BUILD_DIR/lib
    $BUILD_DIR/bin/openssl list -providers -verbose -provider oqsprovider

# -----Set up define the environment variables-----

    nano $HOME/.bashrc

Add the following line

    export WORKSPACE=$HOME/quantumsafe
    export BUILD_DIR=$WORKSPACE/build
    export OPENSSL_CONF=$BUILD_DIR/ssl/openssl.cnf
    export OPENSSL_MODULES=$BUILD_DIR/lib

run

    source $HOME/.bashrc