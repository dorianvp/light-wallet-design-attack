import Lake
open Lake DSL

package zecbreak where
  srcDir := "src"

@[default_target]
lean_lib Zecbreak where
  roots := #[`Zecbreak, `Model, `Breaks, `Soundness]
