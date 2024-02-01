run_outdir=$1
profile=$2
codegen_units=$3
opt_level=$4
strip=$5
lto=$6


run_tmpdir=$run_outdir/tmp
mkdir -p $run_tmpdir

profile_upper=$(tr a-z A-Z <<< $profile)

export CARGO_PROFILE_${profile_upper}_STRIP=$strip
export CARGO_PROFILE_${profile_upper}_LTO=$lto
export CARGO_PROFILE_${profile_upper}_CODEGEN_UNITS=$codegen_units
export CARGO_PROFILE_${profile_upper}_OPT_LEVEL=$opt_level

cargo test -p openmls --profile $profile --target wasm32-unknown-unknown -F js --target-dir=$run_tmpdir || true
wasm_file=$(find $run_tmpdir -name "openmls-*.wasm")

for wasm_opt_O in s z; do
  wasm-opt $wasm_file -O${wasm_opt_O} -o $run_outdir/O${wasm_opt_O}.wasm --enable-simd 
done

rm -r $run_tmpdir


popd

