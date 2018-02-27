# type1ecallfinder

1.Prerequisites:

Make sure you have angr binary analysis framework installed.

* [angr](http://angr.io/) - angr, a binary analysis framework

You may follow [angr documentaion](https://docs.angr.io/INSTALL.html) for installation.

Or a more simple way to install is to install [angr-dev](https://github.com/angr/angr-dev) which has a install script.

After installation of angr, our tool can be used instantly.


2.Run command:

```
bash test.sh
```
You may also uncomment or change the content of test.sh to run different tests. 

All tests in the paper can be run by uncomment lines of test.sh.

And all the authors' tested results are in result folder.

3.File Description:

* [libenclave.signed.so] - A typical SGX enclave .so file.
* [libpal-Linux-SGX.so] - A typical Graphene SGX enclave .so file.
* [enclave.signed.so] - A typical Rust SGX enclave .so file.


