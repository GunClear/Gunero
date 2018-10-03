# Spending within the same sync cycle:
* `a -> b -> a` is allowed
* `a -> b -> a -> b` is not
* `a -> a -> b` is allowed
* `a -> b -> b` is allowed
* `a -> b` then `a -> c` is not
