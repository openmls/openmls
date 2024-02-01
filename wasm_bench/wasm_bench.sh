cargo_workspace_toml=$(cargo locate-project --workspace | jq -r .root)

pushd $(dirname $cargo_workspace_toml)/wasm_bench

set -x

now=$(date +'%y_%m_%d-%H-%M-%S')
outdir=out-$now

## possible value: dev, release
profiles="release"

## default for incremental builds: 256
## default for other builds: 16
## maybe better optimizations: 1
codegen_units_values="1"

## -O flags for rustc. wasm-opt later takes similar ones, but there we always try s and z.
## documentation says z tries stronger than s, but may also be larger than s, and experiments are needed
opt_levels="s z"

## possible values: false, debuginfo, symbols
## technically symbols should be strongest, but so far experiments
## show that debuginfo seems to have a slight lead
strip_values="debuginfo"

# link time optimization; true, false
lto_values="true"


for profile in $profiles; do
  for codegen_units in $codegen_units_values; do
    for opt_level in $opt_levels; do
      for strip in $strip_values; do
        for lto in $lto_values; do
          run_outdir=$outdir/"out_${profile}_strip-${strip}_lto-${lto}_cgu-${codegen_units}_O${opt_level}"
          ./wasm_bench_single.sh $run_outdir $profile $codegen_units $opt_level $strip $lto &
        done
      done
    done
  done
done

wait

popd

