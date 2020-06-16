# BreakingECDSAwithLLL
Breaking ECDSA (not so broken) with LLL

Based on preious work
  ```
https://blog.trailofbits.com/2020/06/11/ecdsa-handle-with-care/
https://www.youtube.com/watch?v=6ssTlSSIJQE
  ```

First install dependencies:
  ```
  sudo apt-get install sagemath python3-ecdsa
  ```

To run:
  ```
  # This will generate 6 weak signatures with a known key e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  python3 weak_signature_generator.py > nonces.csv
  
  # Will break the private key
  python3 crack_weak_ECDSA_nonces_with_LLL.py nonces.csv 176 6 | grep -e e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  ```
