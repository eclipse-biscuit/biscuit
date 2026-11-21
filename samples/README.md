# Biscuit samples and expected results

the `current` folder contains sample tokens and the expected result
of their authorization for the current Biscuit version.

the `deprecated` folder contains samples for the version 0, 1 and 2 of the formats. Those versions are deprecated and should not be used in new implementations.

The authorizer worlds in the samples contain an `elapsed_steps` value, the number of Datalog steps taken by the Rust implementation. It is provided for reference only: the exact step count depends on fact order, which is not specified, so implementations are not expected to match it.
