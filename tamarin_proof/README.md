# Setup

Before you can open the proof files, you must install [Tamarin](https://tamarin-prover.com/).

Once installed, start an interactive Tamarin session in the folder with the proof file by calling:
```bash
tamarin-prover interactive .
```
After some time, this will open a local webserver that you can access by going to `http://127.0.0.1:3001`

Clicking on the `proof` link will load the complete proof. This operation usually takes a long time.

## Encoding error

In case Tamarin shows an encoding error, you can try to run it again as follows:
```bash
LC_ALL=C.UTF-8 tamarin-prover interactive .
```

## Posix error

In case Tamarin shows `posix_spawnp: does not exist (No such file or directory)` ensure that `myoracle.py` is executable:
```bash
chmod +x myoracle.py
```
