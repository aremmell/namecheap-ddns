# namecheap-ddns TODO

* [ ] Add a message to every fatal exception to please file an issue report on GitHub.
* [ ] Add 
  * [x] `--retry` / `--no-retry`
  * [x]  `–retry-after` 
    * [ ] Connection/Timeout errors: starting at 5s, with exponential backoff to 1 minute.
    * [ ] HTTP errors that provide a Retry-After, use that.