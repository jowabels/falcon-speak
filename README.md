# falcon-speak
This is a script used to talk with CrowdStrike Falcon API (assuming you have a valid API account). Their documentation can be found [here](https://falcon.crowdstrike.com/support/documentation).

## Installation
I use virtual environments for everything so if you are like me that don't want to install system-wide Python libraries, packages and want the feeling of having an organized and clean system, just use `venv`.

Clone the repo, make it a virtual environment, and install dependencies using the `requirements.txt` file:
```
git clone https://github.com/jowabels/falcon-speak.git
cd falcon-speak
python -m venv [venv]   # or whatever name you want for the virtual env
pip install -r requirements.txt
```
