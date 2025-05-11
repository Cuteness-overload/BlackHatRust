# BlackHatRust
This repository contains my projects as I work through the Black Hat Rust book by Sylvain Kerkour

While it will mostly mirror what Sylvain's examples, there will be tweaks, additions and improvements (from my PoV).
For instance my simple scanner avoids using mpsc channels as a concurrent stream method and  instead sticks to buffer_unordered + collect. While unifying the code, it also makes it easier to read as I find this method much more elegant in this use case.
