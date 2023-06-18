# namecheap-ddns

A simple, lightweight Python script for updating [Namecheap Dynamic DNS](https://www.namecheap.com/support/knowledgebase/subcategory/11/dynamic-dns) records. You don’t even need to know your public IP address.

`nc-ddns.py` was designed with cron and similar scheduled/event-triggered system daemons in mind. It can just as easily be run manually whenever you like–but that’s not really ideal. We invented computers to do work for us.

### Installation

Well, first, you’re going to need Python. According to a program called vermin that is designed to let you know the minimum version of Python that will run your script properly, you will likely need ≥ 3.7.

##### Dependencies

I am quite sure all or nearly all of the modules imported are already packaged with Python in `/Lib/`.  [requests](https://requests.readthedocs.io/en/latest/user/quickstart/)  and [urllib3](https://urllib3.readthedocs.io/en/stable/user-guide.html) may be exceptions to that rule. Any missing modules can be installed by running `python -m pip install <package>`.





