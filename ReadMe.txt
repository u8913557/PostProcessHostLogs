Pre-requisite:
	1. Python 3.x
	2. python -m pip install --upgrade matplotlib
	3. python -m pip install --upgrade coloram
	
Overview:
	1. Go through host logs and extracts known (pre-defined) pattern and prints them on screen with different color.
	2. Output format:
	
	line#:-[Qtime] pattern_string
	Example:
	#198925:- [ 80914937018 ]  Probe transmitted in Ch # 149; SSID = Linksys02086-_5GHz, BSSID = 60:38:e0:da:99:08
	
How to use:
	1. From CommandPromt:
		python host_parser.py <log_level(Optinal)> <Graphical(Optinal)> host_log
		Example:
		python host_parser.py -vvvvv -G host_driver_logs_current.txt
	2. From Utility GUI:
		Select input host log
		Enter log_level
		Check Graphical 
		
