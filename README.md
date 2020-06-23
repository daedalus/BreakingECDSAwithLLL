# BreakingECDSAwithLLL
Breaking ECDSA (not so broken) with LLL

The main idea behing this attack is the theorem of the great numbers, if you have a crypto funcion and lots of samples (signatures) generated with a private key having a bias in the nonce generation, then they will tend to converge to a single point which happens to be the private key, this is equal to solving the hidden number problem.
And for solving it we employ Lenstra-Lenstra-Lovasz lattice reduction algorithm.

The main counter measure against this kind of attack is using deterministic signatures like Z=H(h||d), where Z is the digest, H is a crypto-secure hash funcion, h the nonce, and d our private key. This is needed in order to have a even distributed, random looking nonce.

Heavily based on previous work
  ```
https://blog.trailofbits.com/2020/06/11/ecdsa-handle-with-care/
https://www.youtube.com/watch?v=6ssTlSSIJQE
  ```

First install dependencies:
  ```
  sudo apt-get install sagemath python3-ecdsa
  ```

Then run:
  ```
  # (Victim) 
  # This will generate 6 weak signatures with a known key, args:(privkey,bits,nonces)
  python3 weak_signature_generator.py e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 176 6 > nonces.csv
  
  # (Attacker) 
  # Will find the private key if LLL converges, args:(bits,nonces)
  python3 crack_weak_ECDSA_nonces_with_LLL.py nonces.csv 176 6 | grep -e e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  ```
