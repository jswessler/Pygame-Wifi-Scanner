# jswessler's WiFi App
# TO:DO
# Add a lot more comments
# Automatically get supported channels/gens
# Color code more things!

from copy import copy
import math, subprocess, threading, os, time
import pygame as pg
import numpy as np
from time import process_time, sleep

try:
    f = open('/Users/jswessler/Desktop/psw.txt', 'r')
    userPassword = f.read()
    f.close()
except:
    pass

if userPassword=='':
    userPassword=input("You need to put in your login password for this analyzer to work! Input it here: ")
    print("If you don't want to have to do this every time, go to line 9 of the python code and put the password there.")
#Your Mac login password. Yeah, I know this is sus. I'm working on a fix for this.

#---Functions
def scan(): #Scans all networks around you using airport scan (or airport -s).
    global nDic,timesScanned,readyToScan,pauseFrame,bssList,phyMode,renderFrame,hold,first,scanStatus,scFrame,lbrCounter,lbrsiEnabled
    stScanTime = process_time()
    scan_cmd = subprocess.getstatusoutput([f'echo %s | sudo -S -k airport scan' % userPassword]) #This line generally takes about 3-4 seconds to run.
    scanOutput = convCmd(scan_cmd)[1:] #Reformat terminal output into a list for processing
    bssList = []
    if updatesPaused: #Immidiately return if updates are disabled and this function is run
        readyToScan=True
        scanStatus = (230,120,20)
        scFrame = 12
        return
    pauseFrame=True #Communicating with main loop, makes it pause on the next frame.
    while hold: #Ghetto aquiring lock so that nDic doesn't change during main loop.
        pass
    if len(scanOutput)==0: #This occasionally happens, waits a bit then returns to try again. Yellow circle if this happens.
        scanStatus = (230,230,20)
        scFrame = 12
        pauseFrame = False
        time.sleep(1.25)
        readyToScan = True
        return
    nDicU={}
    for net in scanOutput: #For each network in the network list
        if net!=[]:
            temp=[]
            if net[1]=='IBSS':
                break
            while net[-3]!='Y' and net[-3]!='N':
                net = net[:-1]
            j = net[0:(len(net)-6)]
            if len(j)>1:
                j=' '.join(j)
            else:
                j=j[0]
            temp.append(str(j)) #Fixed SSID
            temp.append(net[-6]) #BSSID
            temp.append(net[-4]) #Channel
            if net[-1].endswith("')") or net[-1].endswith('")'): #Fix for last entry in the list
                temp.append(net[-1][:-2]) #Security
            else:
                temp.append(net[-1])
            temp.append(int(net[-5])) #RSSI
            temp.append(net[-2]) #Country Code
            if str(net[-6]) in nDic.keys():
                nDic.get(net[-6]).update(net[-5])
            else:
                nDic.update({str(net[-6]): Network(temp[0], temp[1], temp[2], temp[3], temp[4], temp[5])})
            bssList.append(net[-6])
    c3=0
    for net in nDic.copy().values():
        if not net.step():
            pass
    nDic = dict(sorted(nDic.items(), key=lambda item: item[1].ssid))
    nDic = dict(sorted(nDic.items(), key=lambda item: int(item[1].channel)))
    nDic = dict(sorted(nDic.items(), key=lambda item: item[1].avgrssi, reverse=True))
    for net in nDic.values():
        net.updatePos(c3)
        c3+=1
    scanStatus = (120,245,20) #Green for complete
    scFrame = 12
    if lbrsiEnabled:
        lbrCounter+=1
    else:
        lbrCounter=0
    renderFrame=True
    pauseFrame=False
    timesScanned+=1
    first = True
    endScanTime = process_time()
    tme = endScanTime-stScanTime #Time Taken (can detect errors)
    if phyMode=='' or phyMode=='802.11' or timesScanned%10==0: #Will occasionally get your PHY mode if it isn't already known
        scan_cmd = subprocess.getstatusoutput([f'system_profiler SPAirPortDataType'])
        sod = convCmd(scan_cmd)
        scFrame = 12
        try:
            phyMode = (sod[26][2])
            scanStatus = (40,240,240) #Cyan if its successful
        except:
            phyMode = ''
            scanStatus = (40,60,160) #Dark Blue if not
    time.sleep(0.1)
    readyToScan = True

def scanSpd(): #Uses netstat -w command to get your network throughoutput. nTra is [download,upload]
    global nTra,spFrame
    scan_cmd = subprocess.getstatusoutput([f'netstat -w 1 | head -3'])
    sod = convCmd(scan_cmd)
    nTra = [int(sod[2][2]),int(sod[2][5])]
    spFrame = 4
    

def distCalc(rssi,channel=1): #Gets approximate distance from the router using RSSI and channel.
    d = 1
    if channel>11:
        d = math.pow(8.75,(0-float(rssi))/(45+(channel/180)))-1
        err = d/4
    else:
        d = math.pow(9.4,(0-float(rssi))/(42+((channel-1)/30)))-1
        err = d/6
    return round(d,1),round(err,1)

def convCmd(scanout): #Converts terminal outputs to python friendly lists
    scan_out_lines = str(scanout).split("\\n")
    scan_out_data = []
    for each_line in scan_out_lines:
        split_line = [e for e in each_line.split(" ") if e != ""]
        scan_out_data.append(split_line)
    return scan_out_data

def writeData(): #Runs constantly, uses airport info (or -i) to get info about the network you're currently connected to.
    global iLst,iRunCount,gotPhy
    iRunCount+=1
    if iRunCount%30==0 or iLst[9]=='': #Gets your BSSID occasionally (requires sudo, but takes about 0.5s to run)
        gotPhy = True
        scan_cmd = subprocess.getstatusoutput([f'echo %s | sudo -S -k airport info -l' % userPassword])
        #scan_cmd = subprocess.getstatusoutput([f'airport info -l'])
        sod = convCmd(scan_cmd)
        if len(sod)==1 or "AirPort" in sod:
            iLst=[0,0,0,0,"Wifi Off",-1,0,0,0,0,0,'','',0] #Wifi Off
            return
        bss = sod[11][1]
        bssList = bss.split(":")
        temp = ''
        for i in bssList:
            if len(i)==1:
                temp+="0"+i+":"
            else:
                temp+=i+":"
        bss = temp[:-1]
    else:
        scan_cmd = subprocess.getstatusoutput([f'airport info -l'])
        sod = convCmd(scan_cmd)
        if len(sod)==1 or "AirPort" in sod:
            iLst=[0,0,0,0,"Wifi Off",-1,0,0,0,0,0,'','',0] #Wifi Off
            return
        bss = iLst[9]
    try:
        rssi = int(sod[0][3]) #Signal Strength
        ssid = ' '.join(map(str,sod[12][1:])) #Name of network
        noise = int(sod[2][1]) #Noise of network (Generally around -95)
        Tx = int(sod[6][1]) #Transmit rate (Between 11 and 1200)
        Mx = int(sod[7][1]) #Maximum Transmit rate (^^)
        state = str(sod[4][1]) #Various info about connectivity state
        nss = int(sod[15][1]) #Number of spacial signals (improves speed, generally 1, 2 or 4)
        gi = int(sod[14][1]) #Guard interval (generally 400 or 800)
        auth = str(sod[10][2]) #Security of network
        c = sod[16][1] #Channel
        if ',' in c:
            d = c.split(',')
            channel = d[0]
            width=d[1][:2]
        else:
            width=20
            if '"' in c:
                channel = c.split('"')[0]
            else:
                channel = c.split("'")[0]
        iLst=[rssi,noise,Tx,Mx,ssid,channel,state,nss,gi,bss,auth,width] #live data (updated frequently)
    except:
        iLst=[0,0,0,0,"Not Connected",0,0,0,0,0,0,'','',0] #No network

def convertToDict(lis): #Converts Lists to Dicts. 
    lst=[]
    for i in lis:
        j = i.split('\\')
        lst.append(j[0])
        lst.append(j[1])
    res_dct = {lst[i]: lst[i + 1] for i in range(0, len(lst), 2)}
    return res_dct

matWeights = [0.25,0.25,0.25,0.25,0.25,0.25,0.75,1,4.75,5.25,3,0.25]
oneWeights = [0.25,-0.5,-1,-1,-1,-1,-6,-6,-2,-5.5,2.5,0.25]
totWeights = [0.05,0.1,0.25,0.55,0.8,1,1.05,1.1,1.15,1.7,1.95,1.975,2]

def getLinked(cli): #Returns a list of networks that are linked to "cli"
    linked = []
    for j in nDic.values():
        lProb = 0
        mat = 0
        num = 0
        num2=0
        while num<17:
            if cli[num]!=':':
                a = abs(int(cli[num],16)-int(j.bssid[num],16))
                if a==15 or a==14:
                    a=1
                if j.bssid[num]==cli[num]:
                    lProb+=matWeights[num2]
                    mat+=1
                elif a==1 or (a==2 and num2>5):
                    lProb+=oneWeights[num2]
                num2+=1
            num+=1
        lProb*=totWeights[round(mat)]
        lProb-=min(1,abs(nDic[cli].avgrssi-j.avgrssi)*0.1) #Reduction if RSSI's aren't similar (up to 2)
        if abs(nDic[cli].avgrssi-j.avgrssi)>10:
            lProb-=(abs(nDic[cli].avgrssi-j.avgrssi)-10)
        if nDic[cli].ssid!=j.ssid: #Slight reduction if SSID's don't match (up to 2)
            lProb*=0.95
        if nDic[cli].ssid==j.ssid and mat>2: #Boost if slight match, same ssid
            lProb*=1.25
            lProb-=1
        lProb = round(1/(1+math.exp(-0.2825*(lProb-16.25)))*1.0101,4) #Final Sigmoid function
        if lProb>0.3:
            r = max(20,j.color[0]-max(0,(lProb-0.55)*750))
            g = min(240,j.color[1]+(lProb-0.3)*250)
            b = min(240,j.color[2]+max(80,(lProb-0.8)*1050))
            j.updateColor((r,g,b))
        j.updateMsg(lProb)
        if j.bssid==nDic[cli].bssid:
            j.updateColor((230,120,100))
        if lProb>0.6:
            linked.append(j.bssid)
    return sorted(list(set(linked)), key=lambda x: nDic[x].avgrssi)

def secLookup(sec, chn, cc): #Looks up security rating from the dictionary further down.
    global secs
    secValue = -1
    if "NONE" in sec:
        return ["Open Network",(160,160,160),-1]
    for i in secs.items():
        if i[0]==sec.upper():
            if type(i[1])==list:
                secValue = i[1][0]
            else:
                secValue = i[1]
            break
    if secValue==-1:
        print(sec)
        return ["Unknown!",(240,240,20),-1]
    if chn<12 and chn!=1 and chn!=6 and chn!=11:
        secValue-=1
    if cc!="US":
        secValue-=1
    if secValue<1:
        secValue=1
    if secValue>11:
        return ["Excellent",(20,140,255),secValue] #WPA3 networks (mostly iphones)
    elif secValue>9:
        return ["Great",(20,210,240),secValue] #Enterprise/School network
    elif secValue>6:
        return ["Good",(60,230,130),secValue] #Average home network
    elif secValue>3:
        return ["Average",(180,190,110),secValue] #Home networks on weird channels mostly
    elif secValue>1:
        return ["Low",(240,150,50),secValue] #TKIP networks (older routers)
    else:
        return ["Very Low",(240,40,40),secValue] #WEP networks (very old routers)

def textLength(text,text2='',size=True): #Gets textlength of a string, useful for right-aligning text
    if size:
        if pg.mouse.get_pressed()[2] and text2!='':
            tempsurface = font.render(str(text2),False,(20,20,20))
        else:
            tempsurface = font.render(str(text),False,(20,20,20))
    else:
        if pg.mouse.get_pressed()[2] and text2!='':
            tempsurface = smallFont.render(str(text2),False,(20,20,20))
        else:
            tempsurface = smallFont.render(str(text),False,(20,20,20))
    r = tempsurface.get_rect()
    return r.size[0]

def renderText(text, x, y, color, hovDesc='', size=True, cDesc=''): #Code for rendering text and hovering description. Has 2 size options by seting True/False
    if size:
        funcSurface = font.render(str(text), True, color)
        if funcSurface.get_rect(topleft=(int(x),int(y))).inflate(0,-2).collidepoint(pg.mouse.get_pos()):
            funcSurface = font.render(str(text), True, (110,190,245))
            if pg.mouse.get_pressed()[0]:
                funcSurface = font.render(str(text), True, (245,40,40))
            hovSurface = medFont.render(str(hovDesc), True, (100,230,230))
            screen.blit(hovSurface, (WID-10-textLength(str(hovDesc),'',False), HEI-100))
        if pg.mouse.get_pressed()[2] and cDesc!='':
            if funcSurface.get_rect(topleft=(int(x),int(y))).inflate(0,-2).collidepoint(pg.mouse.get_pos()):
                funcSurface = font.render(str(cDesc), True, (110,190,245))
            else:
                funcSurface = font.render(str(cDesc), True, color)
        screen.blit(funcSurface, (int(x),int(y)))
        return funcSurface.get_rect(topleft=(int(x),int(y)))
    else:
        funcSurface = medFont.render(str(text), True, color)
        if funcSurface.get_rect(topleft=(int(x),int(y))).inflate(0,-2).collidepoint(pg.mouse.get_pos()):
            funcSurface = medFont.render(str(text), True, (110,190,245))
            if pg.mouse.get_pressed()[0]:
                funcSurface = medFont.render(str(text), True, (245,40,40))
            hovSurface = medFont.render(str(hovDesc), True, (100,230,230))
            if pg.mouse.get_pressed()[0] and cDesc!='':
                funcSurface = medFont.render(str(cDesc), True, (110,190,245))
            screen.blit(hovSurface, (WID-10-textLength(str(hovDesc),'',False), HEI-100))
        screen.blit(funcSurface, (int(x),int(y)))
        return funcSurface.get_rect(topleft=(int(x),int(y)))

def renderHov(hovDesc): #Renders a hover description ONLY. Used for clickable text.
    hovSurface = medFont.render(str(hovDesc), True, (100,230,230))
    screen.blit(hovSurface, (WID-10-textLength(str(hovDesc),'',False), HEI-100))

def makeNewLists(): #Resets tracking lists when switching networks
    global rssiList,noiseList,txrList
    rssiList = list(np.zeros(100))
    noiseList = list(np.zeros(720))
    txrList = list(np.zeros(180))

def calculateRSum(rssis,c=''): #Calculates RSSI Sum using math.pow. Actually good math!
    sigInArea=0
    for i in rssis:
        if c=='':
            sigInArea+=math.pow(10,(100+float(i.avgrssi))/10)
        elif c==int(i.channel):
            sigInArea+=math.pow(10,(100+float(i.avgrssi))/10)
    s = math.log10(sigInArea)*10-100
    return s

def dFromPt(x,y): #Gets mouse distance from given point
    return (abs(pg.mouse.get_pos()[0]-x)**2 + abs(pg.mouse.get_pos()[1]-y)**2)**0.5

class Network(): #Each network around you is stored as an object
    def __init__(self, s, b, c, se, r, cc):
        self.ssid = s
        self.bssid = b
        self.channel = c
        self.security = se
        self.countryCode = cc
        self.rssi = [int(r)]
        self.de = False
        self.color=(90,90,90)
        self.xpos=0
        self.rect=pg.Rect(0,0,1,1)
        self.ypos=0
        self.defaultColor=self.color
        self.text=''
        self.remrssi = r
        self.avgrssi = int(r)
        self.linked = False
        self.msg = ''
        self.supportedphy = []
        if "+" in self.channel or "-" in self.channel:
            self.channel = int(self.channel.split(',')[0])
        else:
            self.channel = int(self.channel)
        if self.channel<12 and self.channel not in [1,6,11]:
            self.barChn = 1
        else:
            self.barChn = self.channel
    def update(self, r): #Run every update frame
        self.remrssi = self.rssi[-1]
        if lbrsiEnabled:
            self.rssi.append(int(r))
            if len(self.rssi)>10:
                self.rssi.pop(0)
        else:
            self.rssi = [int(r)]
    def updatePHY(self, phys, ssid): #Run whenever needed. UNUSED AT THE MOMENT
        self.supportedphy=phys
        self.supposedssid = ssid
    def step(self): #Runs every update frame.
        self.avgrssi = round(sum(self.rssi)/len(self.rssi),1)
        if self.bssid not in bssList:
            self.de=True
            nDic.pop(self.bssid)
            return True
        else:
            self.de=False
            return False
    def updateColor(self,c): #Runs whenever there's a color change
        self.color = c
        self.text = smallFont.render(str(self.ssid),True,(c))
        if c==(150,180,150) or c==(180,150,150) or c==(90,110,90) or c==(110,90,90):
            self.defaultColor=c
    def updateMsg(self,msg=''):
        if msg=='':
            self.msg = -1
        else:
            self.msg = min(1,float(msg))
    def updatePos(self,n=''): #Run every update frame + some other frames to update screen position of the text. THIS NEEDS UPDATING
        if n!='':
            self.num = n
        mod = max(6,(HEI/15)-10)
        self.xpos = (self.avgrssi+10)*((WID-55)/95)+WID-35
        self.ypos = 53+(self.num%mod)*9
        self.text = smallFont.render(str(self.ssid),True,(self.color))
        self.rect = self.text.get_rect()
        for i in range(self.num-int(mod),0,-int(mod)):
            if list(nDic.values())[i].rect.left<self.rect.right:
                self.rect.move_ip(-10,0)
                self.xpos-=10
    def render(self): #Draws itself to screen
        screen.blit(self.text if not pg.mouse.get_pressed()[2] else smallFont.render(str(self.bssid),True,(self.color)),(self.xpos,self.ypos))
        if self.msg!=-1:
            renderText(str(round(self.msg*100,1)) + "%",self.xpos+10+textLength(self.ssid,self.bssid,False),self.ypos,(min(240,80+(max(0,(self.msg-0.005)*7200))),min(240,80+(self.msg*1440)),min(240,80+(self.msg*360))) if self.msg<0.6 else (20,240,240),'',False)
#---User-Defined Parameters

secs = { #Dictionary of network securities
    "RSN(PSK/AES/AES)": 8,
    "WPA(PSK/AES/AES)": 6,
    "RSN(802.1X/AES/AES)": 10,
    "WPA(802.1X/AES/AES)": 9,

    "WPA(802.1X/AES,TKIP/TKIP)": 5,

    "RSN(PSK,SAE/AES/AES)": 12,
    "RSN(SAE/AES/AES)": 11,

    "RSN(PSK,FT-PSK/AES/AES)": [9,'802.11r Cert'],
    "RSN(PSK,FT-PSK/TKIP,AES/TKIP)": [5,'802.11r Cert'],
    "RSN(802.1X,FT-802.1X/AES/AES)": [11, '802.11r Cert'],

    "RSN(PSK/AES,TKIP/TKIP)": 3,
    "WPA(PSK/AES,TKIP/TKIP)": 2,
    "RSN(PSK/TKIP,AES/TKIP)": 3,
    "WPA(PSK/TKIP,AES/TKIP)": 2,
    "WPA(PSK/TKIP/TKIP)": 2,
    "RSN(PSK/TKIP/TKIP)": 4,

    "RSN(802.1X,UNRECOGNIZED(0)/AES/AES)": 7,
    "RSN(PSK,PSK-SHA256/AES/AES)": 9,

    "WEP": 1
}

gens = ['a', 'b', 'g', 'n', 'ac', 'ax'] #Dictionary of network generations. This assumes you have WiFi 6
spds = [11, 54, 54, 144, 400, 867] #Dictionary of network speeds.
cols = [(45,230,205),(210,55,20),(245,130,20),(225,200,20),(75,245,20),(230,35,245)] #Colors used for different generations

channelList = [1, 6, 11, 36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]
# Change if your mac has different channels it can connect to. (Will be automated in the future)

hold = readyToScan = ableToType = showSpds = secCircles = True
renderFrame = updatesPaused = pauseFrame = done = stopClick = gotPhy = lbrsiEnabled = False
iRunCount = timesScanned = maxSpd = hovData = counter = rememberRssi = scFrame = spFrame = avgSec = avgDiff = lbrCounter = lbrDiff = remLbr = nTra = downSpd = upSpd = 0
avgLbr = 1.01
remHov = -1
barsMaxHeight = updateSpeed = fpsSetting = 1
chnSig = phyMode = clickNum = storeSsid = clickData = currentTxt = hovNum = ''
txtCol = txtPos = rectList = bssList = whiteLines = []
lbrsi = {}
nDic = {}
iLst=[0,0,0,0,"Not Connected",0,0,0,0,0,0,0]
fps = 30
scanStatus = (0,0,0)

makeNewLists()
fpsList = list(np.zeros(60))
spdList = []
while len(spdList)<120:
    spdList.append([0,0])
pg.init()
pg.display.set_caption("jswessler's WiFi App", "WiFi")
font = pg.font.SysFont('None', 25)
medFont = pg.font.SysFont('None', 18)
smallFont = pg.font.SysFont('None', 16)

f = open('notes.txt', 'r')
tLines = f.readlines()
notesLines = convertToDict(tLines)
f.close()

f = open('bssid.txt', 'r')
lines = f.readlines()
bsLookupDic = {}
for i in lines:
    bsLookupDic.update({str(i[0:2]) + ":" + str(i[2:4]) + ":" + str(i[4:6]): str(i[7:-1])})
f.close()

WID = 960
HEI = 600
screen = pg.display.set_mode((WID, HEI), pg.RESIZABLE)
remWidth = WID
remHeight = HEI
wi2 = 72
wi5 = 573
wit = WID-wi2-wi5-145

while not done: #Main pygame loop
    moving,hold,unknown=[False,False,False]
    startTimer = process_time()
    clock = pg.time.Clock()
    all_events = [e for e in pg.event.get()]
    for e in all_events:
        if e.type == pg.QUIT:
            done = True
    if len(nDic)==0:
        try:
            if iLst[5]==-1:
                bgColor = (24,24,24)
            else:
                bgColor = (40,30,30)
        except:
            bgColor = (24,24,24)
    else:
        bgColor = (40,40,40)
    screen.fill(bgColor)
    if pg.mouse.get_pos()[0]<WID/20 and pg.mouse.get_pos()[1]<HEI/22:
        r = pg.Rect(0,0,WID/20,HEI/22)
        if pg.mouse.get_pressed()[0]:
            clickNum,clickData = ['','']
            pg.draw.rect(screen, (180,20,20,0.25),r)
        else:
            pg.draw.rect(screen, (20,160,180,0.25),r)
#Calculate bottom bar scaling, mouse pos. THIS COULD USE UPDATING --------------------------------------------------------------------------
    xmouse,ymouse = pg.mouse.get_pos()
    if ymouse<HEI-10 and ymouse>HEI-40:
        if xmouse>wi2-50 and xmouse<wi2+150 and pg.mouse.get_pressed()[0]:
            if offset=='':
                offset = xmouse-wi2-15
            moving = True
            wi2 = xmouse-15-offset
            if wi2<48:
                wi2=48
            wi5=WID-wi2-wit-145
        if xmouse>wi2+wi5 and xmouse<wi2+wi5+200 and pg.mouse.get_pressed()[0]:
            if offset=='':
                offset = xmouse-wi2-wi5-65
            moving = True
            wi5 = xmouse-wi2-65-offset
            if wi5<120:
                wi5=120
            wit = WID-wi2-wi5-145
            if wit<75:
                wit=75
                wi5 = WID-wi2-wit-155
    if wi2!=72 or wi5!=573 or wit!=170:
        if (math.pow(xmouse-8,2))+(math.pow(ymouse-(HEI-24),2))<144:
            pg.draw.circle(screen, (110,190,245),(8,HEI-24),5)
            renderHov("Click to reset bottom row scales.")
            if pg.mouse.get_pressed()[0]:
                wi2 = 72
                wi5 = 573
                wit = 170
                moving = True
        else:
            pg.draw.circle(screen, (160,160,160),(8,HEI-24),5)
    if not moving:
        offset = ''
# Starting off, reset lists, set scan delay --------------------------------------------------------------------------
    if iLst[6]=='init' or iLst[6]=='associating' or iLst[6]=='authenticating' or iLst[-3]==0:
        delay = 2
    if updateSpeed==2:
        delay = 4
    elif updateSpeed==1:
        delay = 12
    else:
        delay = 36
    if iLst[6]=='init':
        delay = fps/2
    if iLst[5]==-1 and len(nDic)<0:
        delay = -1
    if delay!=-1 and counter%math.ceil(delay)==0:
        iLFrame = 4
        gotPhy = False
        t = threading.Thread(target=writeData)
        t.start()
    if readyToScan and not updatesPaused:
        readyToScan=False
        t = threading.Thread(target=scan)
        t.start()
    if counter%(65+delay) == 1 and showSpds:
        t = threading.Thread(target=scanSpd)
        t.start()
    if iLst[4]!="Not Connected":
        rssiList.pop(-1)
        rssiList.insert(0,iLst[0])
        noiseList.pop(-1)
        noiseList.insert(0,iLst[1])
        txrList.pop(-1)
        txrList.insert(0,iLst[2])
        spdList.pop(-1)
        spdList.insert(0,nTra)
    while pauseFrame:
        pass
# Draw RSSI circles, draw main bars and lines --------------------------------------------------------------------------
    averageRssi = sum(rssiList)/(1+min(counter,100-1))
    averageRssi = round(averageRssi,4)
    averageNoise = sum(noiseList)/(1+min(counter,720-1))
    averageNoise = round(averageNoise,4)
    avgTxr = round(sum(txrList)/(1+min(counter,180-1)),1)
    pg.draw.line(screen, (200,200,200), (15,40), (WID-40,40), 2) #main bar 15-920 (905 length, WID-55)
    pg.draw.circle(screen, (50,80,240), (int((averageRssi+10)*((WID-55)/95)+(WID-40)),41),10)
    renderText(round(averageRssi,2), ((averageRssi+10)*((WID-55)/95))+(WID-59),15,(230,230,230),"Current RSSI (Signal Strength) of connected network.",True,str(distCalc(averageRssi,int(iLst[5]))[0]) + " Ft")
    pg.draw.circle(screen, (160,50,230), (int((averageNoise+10)*((WID-55)/95))+(WID-40),41),10)
    renderText(round(averageNoise,2), ((averageNoise+10)*((WID-55)/95))+(WID-59),15,(220,220,220),"Current Noise of connected network.",True,str(distCalc(averageNoise*0.99+2,int(iLst[5]))[0]) + " Max")
    if averageRssi>rememberRssi:
        for i in range(0,max(1,min(6,round(75*(averageRssi-rememberRssi))))):
            pg.draw.line(screen, (20,255,20), ((int((averageRssi+10+i)*((WID-55)/95))+WID-5,30)), ((int((averageRssi+10+i)*((WID-55)/95))+WID+5,20)), 4)
            pg.draw.line(screen, (20,255,20), ((int((averageRssi+10+i)*((WID-55)/95))+WID-5,10)), ((int((averageRssi+10+i)*((WID-55)/95))+WID+5,20)), 4)
    elif rememberRssi>averageRssi:
        for i in range(0,max(1,min(6,round(40*(rememberRssi-averageRssi))))):
            pg.draw.line(screen, (255,20,20), ((int((averageRssi+10-i)*((WID-55)/95))+WID-65,30)), ((int((averageRssi+10-i)*((WID-55)/95))+WID-75,20)), 4)
            pg.draw.line(screen, (255,20,20), ((int((averageRssi+10-i)*((WID-55)/95))+WID-65,10)), ((int((averageRssi+10-i)*((WID-55)/95))+WID-75,20)), 4)
    ba5 = 65+wi2
    bat = ba5+wi5+50
    pg.draw.line(screen, (160,80,80), (15,HEI-25), (15+wi2,HEI-25),2) #72px / 3 channels = 24
    pg.draw.line(screen, (80,160,80), (65+wi2,HEI-25), (ba5+wi5,HEI-25),2) #416px / 26 channels = 16
    for i in nDic.values():
        if i.color!=(150,180,150) and i.color!=(180,150,150) and i.color!=(90,110,90) and i.color!=(110,90,90):
            i.updateColor(i.defaultColor)
# Handle scan results on update frames --------------------------------------------------------------------------
    if renderFrame: #ON UPDATE FRAMES
        verticalDist=0
        nameList = []
        shownInfo = -1
        txtCol = []
        knownNetworks=0
        txtPos = []
        hold=True
#Initializing default colors and values --------------------------------------------------------------------------
        sigInArea=calculateRSum(nDic.values())
        for i in nDic.values():
            avgLbr+=len(i.rssi)
            avgDiff+=abs(i.rssi[-1]-int(i.remrssi))*max(0.5,math.log10(i.avgrssi+110)-1) if i.avgrssi>-110 else 0
            nameList.append(i.ssid)
            if any(v==str(i.bssid) for v in notesLines): #If the network is known
                knownNetworks+=1
                if i.channel>11: #Shades of green if 5ghz
                    i.updateColor((150,180,150))
                else:
                    i.updateColor((180,150,150))
            else:
                if i.channel>11: #Shades of red if 2.4ghz
                    i.updateColor((90,110,90))
                else:
                    i.updateColor((110,90,90))
        if len(nDic)>0:
            avgLbr/=len(nDic)
            avgDiff/=len(nDic)
            lbrDiff = avgLbr-remLbr
            remLbr = avgLbr
        else:
            avgLbr = 1.0
            avgDiff = 0.0 #These 2 variables relate to the bars on the top right
#Sorting Flux List, determining scale factor for bars --------------------------------------------------------------------------
        barsMaxHeight=0
        for i in range(0,len(channelList)):
            tempHeight=0
            for j in nDic.values():
                if j.barChn==channelList[i]:
                    tempHeight+=max(max(5,13-math.floor(math.sqrt(len(nDic)*2))),2*int(math.pow(100+j.avgrssi,2)))
            if barsMaxHeight<tempHeight:
                barsMaxHeight=tempHeight
#Making Rectangles for Bar Graph --------------------------------------------------------------------------
    if renderFrame or moving:
        rectList = []
        whiteLines = []
        for i in range(0,len(channelList)):
            totalHeight = 0
            for j in nDic.values():
                tempHeight=0
                if j.barChn==channelList[i]:
                    tempHeight = max(max(5,13-math.floor(math.sqrt(len(nDic)*2))),int(((30+(HEI/2.75))/barsMaxHeight)*2*math.pow(100+j.avgrssi,2))) #___/m = max height of bars
                    if i<3:
                        r = pg.Rect(int(i*(wi2/3)+15),HEI-25-tempHeight-totalHeight,(wi2/3)-1,tempHeight)
                        wl = [i*(wi2/3)+15,HEI-25-totalHeight,i*(wi2/3)+(13+wi2/3),HEI-25-totalHeight]
                    else:
                        r = pg.Rect((i-3)*(wi5/25)+(wi2+65),HEI-25-tempHeight-totalHeight,wi5/25-1,tempHeight)
                        wl = [(i-3)*(wi5/25)+(wi2+65),HEI-25-totalHeight,(i-2)*(wi5/25)+(wi2+65)-2,HEI-25-totalHeight]
                    totalHeight+=tempHeight
                    rectList.append([r,j.bssid,j.channel,j.avgrssi,j.ssid])
                    whiteLines.append(wl)
        rectList.sort(key=lambda x: x[4])
        rectList.sort(key=lambda x: int(x[2]))
        rectList.sort(key=lambda x: x[3], reverse=True) #Same sorting as nDic
    b=[]
#Calculate selected channel's signal strength --------------------------------------------------------------------------
    for i in rectList:
        if i[0].collidepoint(pg.mouse.get_pos()):
            chnSig=calculateRSum(nDic.values(),c=int(i[2]))
            break
        else:
            chnSig=''
    if chnSig!='':
        renderText(str(round(abs(chnSig),2)),bat-45,HEI-51,(230,230,230))
        pg.draw.line(screen, (20,160,160) if int(i[2])>11 else (160,20,160), (int((chnSig+10)*((WID-55)/95)+(WID-40)),31),(int((chnSig+10)*((WID-55)/95)+(WID-40)),51),2) #Draws a line on the main bar that represents the RSSI of that channel
    try:
        pg.draw.line(screen, (20,240,100), (int((sigInArea+10)*((WID-55)/95)+(WID-40)),31),(int((sigInArea+10)*((WID-55)/95)+(WID-40)),51),2)
    except:
        pass
#Testing Hov and Click --------------------------------------------------------------------------
    linked = []
    for i in nDic.values():
        if i.num<len(rectList) and rectList[i.num][0].collidepoint(pg.mouse.get_pos()):
            hovNum,hovData = [i.num,i.bssid]
            for j in nDic.values():
                if j.channel==i.channel:
                    j.updateColor((240,180,220)) #Pink if the channels are the same
            if pg.mouse.get_pressed()[0]:
                clickNum,clickData=[i.num,i.bssid]
        if i.text.get_rect(topleft=(i.xpos,i.ypos)).inflate(0,-2).collidepoint(pg.mouse.get_pos()):
            hovNum,hovData = [i.num,i.bssid]
            if pg.mouse.get_pressed()[0]:
                clickNum,clickData=[i.num,i.bssid]
#Further Color Calculations --------------------------------------------------------------------------
    if hovNum=='':
        if clickNum!='':
            try:
                hovNum,hovData = [clickNum,clickData]
            except:
                hovNum,hovData = ['','']
    if hovData not in nDic.keys():
        hovNum,hovData = ['','']
        if clickNum not in nDic.keys():
            clickNum,clickData = ['','']
    for i in nDic.values():
        if i.bssid==iLst[9]:
            i.updateColor((40,255,40)) #Bright Green if its the one you're connected to
    if hovNum!='':
        linked = getLinked(nDic[hovData].bssid)
    else:
        for i in nDic.values():
            i.updateMsg()
    if clickNum!='':
        try:
            clickNum = list(nDic.keys()).index(clickData)
            nDic[clickData].updateColor((240,20,20)) #Bright red if clicked on
        except:
            pass
        c3=0
#Rendering RSSI View & Bar Graph --------------------------------------------------------------------------
    try:
        HOV=nDic[hovData]
        if hovNum!='': #Draws a line and circle connecting back to the top bar
            pg.draw.line(screen, (160,160,160), (HOV.xpos-6,HOV.ypos), (HOV.xpos-6, 40), 2)
            pg.draw.circle(screen, (160,160,160), (HOV.xpos-5,41), 5)
    except:
        pass
    scTemp=0
    c3=0
    for i in nDic.values():
        scTemp = secLookup(i.security,i.channel,i.countryCode)
        if secCircles:            
            pg.draw.circle(screen, scTemp[1], (i.xpos-5, i.ypos+4), 3) #Draws a circle next to each name for security
        try:
            avgSec+=scTemp[2]
            if scTemp[0]=="Unknown":
                unknown = True
        except:
            pass
        i.render()
        try:
            pg.draw.rect(screen, i.color, rectList[c3][0])
        except IndexError as e:
            raise Exception("Your mac has different channels it connects to. Edit line 451") from e
        c3+=1
   
    #Render Diff bar on the top right (Middle)--------------------------------------------------------------------------
    if avgDiff<1:
        pg.draw.line(screen, tuple(max(80,int(i)*int(scFrame)/12) for i in scanStatus) if scFrame>0 and avgDiff<1.9 else (80,80,80),(WID-20,56),(WID-20,26),5)
    if avgDiff>=1.9 and scFrame!=0:
        pg.draw.circle(screen, (tuple(max(40,int(i)*int(scFrame)/12) for i in scanStatus)),(WID-20,64),5)
    pg.draw.line(screen, (200+min(40,avgDiff*5),80-max(40,avgDiff*5),40) if avgDiff>2 else (100+(math.pow(avgDiff*2.6,3)),240-(math.pow(avgDiff*2.925,3)),40),(WID-20,56),(WID-20,56-min(avgDiff*15,30)),5)
    if pg.Rect(WID-25,28,10,26).collidepoint(pg.mouse.get_pos()):
        renderText(str(round(avgDiff,2)),WID-10-textLength(str(round(avgDiff,2))),HEI-120,(230,230,230))
        renderHov("Shows average delta in network signals over time.")
    
    #Render LBR bar on the top right (Left)--------------------------------------------------------------------------
    if lbrsiEnabled:
        pg.draw.line(screen, (80,80+scFrame*13.333,80+scFrame*13.333) if lbrDiff>1 else (80,80+scFrame*lbrDiff*13.333,80) if lbrDiff>0 else (140,140,80) if lbrCounter==0 else (80,80,80), (WID-30,56),(WID-30,26),5)
        if lbrCounter!=0:
            pg.draw.line(screen, (40,240,40) if avgLbr<8 else (np.clip(40-scFrame*(60*lbrDiff),40,240),240,np.clip(240*(avgLbr-9)+(40+scFrame*(60*lbrDiff)),40,240)), (WID-30,56), (WID-30,56-min(30,avgLbr*3.3333)),5)    
    else:
        pg.draw.line(screen, (120,80,80), (WID-30,56),(WID-30,26),5)
    if pg.Rect(WID-35,26,10,30).collidepoint(pg.mouse.get_pos()):
        renderHov("Click to toggle LBR.")
        renderText(str(round(avgLbr,2)) + "/10",WID-10-textLength(str(round(avgLbr,2)) + "/10"),HEI-120,(230,230,230))
        if pg.mouse.get_pressed()[0] and not stopClick:
            lbrsiEnabled = not lbrsiEnabled
            stopClick = True
    
    #Render Quality bar on the top right (Right)--------------------------------------------------------------------------
    if iLst[7]!=-1 and iLst[5]!=-1 and iLst[4]!="None":
        qual = round(sum(rssiList[0:10])/10-sum(noiseList[0:50])/50,3)
        if qual>=0 and qual<50:
            pg.draw.line(screen,(80,80,80) if qual>10 else (80+(40-(qual*4)),80+(20-(qual*2)),80-(40-(qual*4))),(WID-10,56),(WID-10,26),5)
        pg.draw.line(screen, (240,40-qual,20) if qual<0 else (240-(qual*4),140+(qual*2),80) if qual<50 else (20,200,240), (WID-10,56),(WID-10,56-min(qual/1.666,30)) if qual>=0 else (WID-10,26),5)
        if pg.Rect(WID-15,28,10,26).collidepoint(pg.mouse.get_pos()):
            renderText(str(min(50,round(qual,1))) + "/50",WID-10-textLength(str(min(50,round(qual,1))) + "/50"),HEI-120,(230,230,230))
            renderHov("Shows quality of your connection.")
    
    #Render bottom dynamic text and bar lines --------------------------------------------------------------------------
    if len(nDic)>0:
        pg.draw.line(screen,((80+scFrame*6,80+scFrame*6,80+scFrame*6)),(bat-45,HEI-24),(bat-5,HEI-24),7)
        pg.draw.line(screen,(sigInArea*-2.4,240-sigInArea*-2.4,40),(bat-45,HEI-24),(bat-45+(40-sigInArea/-2.5),HEI-24),7)
        r = pg.Rect(bat-45,HEI-34,40,20)
        if r.collidepoint(pg.mouse.get_pos()):
            renderText(round(abs(sigInArea),2), bat-45, HEI-51, (230,230,230), "Total flux in area. (Estimate only)")
        
        
        
        avgSec/=len(nDic)+1
        if unknown:
            txtRect = renderText(round(avgSec,3), 30+wi2, HEI-31, (255,255,0), "Network with unknown security! Time to fill it in!")
        else:
            txtRect = renderText(round(avgSec,3), 20+wi2, HEI-31, (max(0,255-(avgSec*36)), max(0,(6-abs(avgSec-6))*42.5), max(0,(avgSec-7)*52)), "Average security of nearby networks from 1-12")
            if txtRect.inflate(0,-2).collidepoint(pg.mouse.get_pos()) and pg.mouse.get_pressed()[0] and not stopClick:
                secCircles = not secCircles
                stopClick = True
    for i in range(0,len(whiteLines)):
        pg.draw.line(screen, (240,240,240), whiteLines[i][0:2], whiteLines[i][2:], 1)
    renderFrame=False
#Rendering Info Text & Handling User Input --------------------------------------------------------------------------
    if hovNum!='':
        i=nDic[hovData]
        netName=str(i.ssid)
        try:
            channel = str(i.channel).split(',')[0]
        except:
            channel = i.channel
        if int(channel)>11:
            colSet = (100,190,100)
        else:
            colSet = (190,100,100)
        f = open('notes.txt', 'r') #notes.txt contains user notes on network BSSID's
        g = f.readlines()
        if ableToType:
            currentTxt = notesLines.get(str(i.bssid), '')
        if currentTxt!='' and currentTxt[-1]=="\n":
            currentTxt = currentTxt[:-1]
        for e in all_events:
            if e.type == pg.KEYDOWN:
                if e.key == pg.K_RETURN: #Finalize and store new note in the txt file.
                    flines=[]
                    if pg.mouse.get_pos()[0]<WID/18 and pg.mouse.get_pos()[1]<HEI/20 or pg.mouse.get_pressed()[2]: #If your mouse is in the box, it will save this note to most linked networks.
                        for j in nDic.values():
                            if j.msg>0.6:
                                flines.append(j)
                    else:
                        flines.append(i)
                    f = open('notes.txt', 'r')
                    tt = f.read()
                    notesLines=tt.split('\n')
                    f.close()
                    bs=[]
                    for q in flines:
                        notesLines.append(str(q.bssid) + "\\" + str(currentTxt)) #Forward slash delimiter
                    for line in notesLines[::-1]:
                        if line[0:17] in bs:
                            notesLines.pop(notesLines.index(line)) #Takes out existing note
                        else:
                            bs.append(line[0:17]) #Puts in new note
                    f = open('notes.txt', 'w')
                    f.write('')
                    for line in notesLines[:-1]:
                        f.write(line + "\n")
                    f.write(notesLines[-1])
                    f.close()
                    ableToType = True
                    currentTxt = ''
                    f = open('notes.txt', 'r')
                    tLines = f.readlines()
                    notesLines = convertToDict(tLines) #Updates the "notesLines" varible to have new known networks without having to wait for an update
                    f.close()
                    renderFrame=True
                elif e.key == pg.K_BACKSPACE:
                    currentTxt = currentTxt[:-1]
                    ableToType = False
                else:
                    currentTxt += e.unicode
                    ableToType = False
        renderText(currentTxt,WID-10-textLength(currentTxt),HEI-120,(230,230,230),"User-Inputted description for this network.")
#Display data when hovering over a network ----------------------------------------------------------------------------       
        if bLookup=='' or remHov!=hovNum:
            try:
                bLookup = bsLookupDic[i.bssid.upper()[0:8]]
                bColor = (230,230,230)
            except:
                for j in nDic.values():
                    if nDic[i.bssid].bssid[2:15]==j.bssid[2:15] and i!=j:
                        try:
                            bLookup = bsLookupDic[j.bssid.upper()[0:8]]
                            bColor = (60,100,200)
                            break
                        except:
                            pass
        if bLookup=='':
            renderText("Unknown",WID-10-textLength("Unknown",str(i.bssid)),HEI-160,(160,160,160),"Manufacturer of this network's router.",True,str(i.bssid))
        else:
            renderText(bLookup,WID-10-textLength(bLookup,str(i.bssid)),HEI-160,(bColor),"Manufacturer of this network's router.",True,str(i.bssid))
        remHov=hovNum
        d,e = distCalc(i.avgrssi, int(channel))
        renderText("RSSI: " + str(round(i.avgrssi,1)) + " - " + str(len(i.rssi)), WID-10-textLength("RSSI:" + str(round(i.avgrssi,1)) + " - " + str(len(i.rssi)),str(d) + " +/- " + str(e) + " Feet"),HEI-180,(230,230,230) if i.avgrssi>-80 else (max(120,240-(i.avgrssi+80)*-6),max(120,240-(i.avgrssi+80)*-12),max(120,240-(i.avgrssi+80)*-12)),"Signal strength of this network / Accuracy from 1-10.",True,str(d) + " +/- " + str(e) + " Feet")
        renderText("SSID: " + netName, WID-10-textLength("SSID: " + netName,"SSID: " + netName + " - Channel: " + str(channel)),HEI-200, colSet, "SSID of this network", True,"SSID: " + netName + " - Channel: " + str(channel))
        if iLst[9]==i.bssid:
            renderText("Current Network", WID-10-textLength("Current Network"),HEI-220,(40,240,40))
        r,c,v = secLookup(i.security,i.channel,i.countryCode)
        renderText(r + " Security (" + str(v) + ")" if v!=-1 else r, WID-10-textLength(r + " Security (" + str(v) + ")" if v!=-1 else r,str(i.security) if (i.bssid!=iLst[9]) else str(iLst[10])), HEI-140, c, "Security rating of this network. Sort of subjective.",True, str(i.security) if (i.bssid!=iLst[9]) else str(iLst[10]))
    else:
        bLookup=''
        descRects=[]
#Dynamic Text--------------------------------------------------------------------------
    maxSpd = int(iLst[3])
    probGen=''
    colSet = (220,220,220)
    try:
        colSet = cols[gens.index(phyMode[6:])] #Gets the current color set using the phy mode
    except:
        try: #tries to get a probable phymode using the wifi speed. this doesn't work all the time (which is why its in a try)
            colSet = cols[spds.index(maxSpd)]
            probGen = spds.index(maxSpd)
            if maxSpd==54: #Both b and g have max speed of 54, differentiate them by channels (2.4ghz vs 5ghz)
                if int(iLst[5])<11:
                    colSet = cols[2]
                    probGen=2
                else:
                    colSet = cols[1]
                    probGen=1
            colSet = tuple(round(ti/1.5) for ti in colSet) #Makes everything darker because its only a "probable" phymode
        except:
            pass
    if iLst[4]=="None":
        colSet = (80,80,80)
    if iLst[7]==0:
        pg.draw.line(screen, tuple(round(ti/2) for ti in colSet), (WID-20,HEI-34), (WID-20,HEI-14), 5)
    elif iLst[8]==400: #Renders one or two bars on the bottom right of the screen (corresponds to NSS and GI)
        if iLst[7]==2: #if there are 2 NSS, draw 2 lines
            if iLst[6]=="scanning":
                pg.draw.line(screen, (colSet), (WID-20,HEI-34), (WID-20,HEI-14),5)
            else:
                pg.draw.line(screen, (230,230,230), (WID-20,HEI-34), (WID-20,HEI-14),5)
            pg.draw.line(screen, (20,200,240), (WID-10,HEI-34), (WID-10,HEI-14),5)
        elif iLst[7]==1:
            if iLst[6]=="scanning":
                pg.draw.line(screen, (20,200,240), (WID-20,HEI-34), (WID-20,HEI-14),5)
            else:
                pg.draw.line(screen, (230,230,230), (WID-20,HEI-34), (WID-20,HEI-14),5)
    else: #If guard interval is 800 (slightly slower)
        if iLst[7]==2: #if there are 2 NSS
            if iLst[6]=="scanning":
                pg.draw.line(screen, (colSet), (WID-20,HEI-34), (WID-20,HEI-14),5)
            else:
                pg.draw.line(screen, (230,230,230), (WID-20,HEI-34), (WID-20,HEI-14),5)
            pg.draw.line(screen, (240,200,20), (WID-10,HEI-34), (WID-10,HEI-14),5)
        elif iLst[7]==1:
            if iLst[6]=="scanning":
                pg.draw.line(screen, (240,200,20), (WID-20,HEI-34), (WID-20,HEI-14),5)
            else:
                pg.draw.line(screen, (150,150,150), (WID-20,HEI-34), (WID-20,HEI-14),5)
    if not any(s==0 for s in spdList):
        downSpd = sum(s[0] for s in spdList)/15
        upSpd = sum(s[1] for s in spdList)/15
        if showSpds:
            displayDS = str(round(downSpd/1024,1)) + "Kb/s" if downSpd<100000 else str(round(downSpd/1024)) + "Kb/s" if downSpd<1000000 else str(round(downSpd/1048576,1)) + "Mb/s"
            displayUS = str(round(upSpd/1024,1)) + "Kb/s" if upSpd<100000 else str(round(upSpd/1024)) + "Kb/s" if upSpd<1000000 else str(round(upSpd/1048576,1)) + "Mb/s"
    if iLst[5]==-1: #iLst[5] is set to -1 if Wifi is manually disabled
        renderText("WiFi Off",10,60,(240,120,120),"WiFi is currently disabled.")
    else:
        if iLst[6]=='init':
            renderText("Disconnected" if iLst[7]==-1 else "Disconnecting...",10,60,(200,160,80) if iLst[7]==-1 else (220,140,80),"Currently disconnected from WiFi.")
        elif iLst[6]=='authenticating': #currently connecting to a network
            renderText("Connecting...",10,60,(160,190,160),"Connecting to this network.")
        elif iLst[6]=='associating': #currently connecting to a network
            renderText("Connecting...",10,60,(90,245,95),"Almost connected to this network!")
        elif iLst[7]==-1: #Not connected but wifi is still on
            renderText("Disconnected",10,60,(220,140,80),"Currently disconnected from WiFi. Searching...")
            phyMode=''
        else:
            if avgTxr!=0:
                if showSpds:
                    txtrect = renderText(str(displayDS),bat+10+textLength(str(round(avgTxr)) + "/" + str(maxSpd) + "Mb/s"),HEI-65,(230,230,230),"Download Speed",True,str(round(downSpd/1048576/avgTxr*100,2)) + "%")
                    txtrect2 = renderText(str(displayUS),bat+10+textLength(str(round(avgTxr)) + "/" + str(maxSpd) + "Mb/s"),HEI-85,(230,230,230),"Upload Speed",True,str(round(upSpd/1048576/avgTxr*100,2)) + "%")
                else:
                    txtrect = renderText("Off",bat+10+textLength(str(round(avgTxr)) + "/" + str(maxSpd) + "Mb/s"),HEI-75,(160,160,160),"Click to turn on throughtput tracking.")
                if (txtrect.inflate(0,-2).collidepoint(pg.mouse.get_pos()) or txtrect2.inflate(0,-2).collidepoint(pg.mouse.get_pos())) and pg.mouse.get_pressed()[0] and not stopClick:
                    showSpds = not showSpds
                    stopClick = True
            txtrect = renderText(str(iLst[4]), 10,60,(230,230,230),"Shows Current SSID. Click to select this network.",True,str(iLst[9]) if iLst[9]!=0 else "Finding BSSID...")
            if txtrect.inflate(0,-2).collidepoint(pg.mouse.get_pos()) and pg.mouse.get_pressed()[0] and len(nDic)!=0:
                for i in nDic.keys():
                    if i==iLst[9]:
                        clickNum=list(nDic.keys()).index(i)
                        clickData=i
                        break
    if len(nDic)==0 and iLst[5]!=-1 and timesScanned>0: #If there are no networks around after checking at least once
        txtrect = renderText("No Nearby Networks",10,80,(240,20,20),"No nearby networks to scan!")
    elif updatesPaused: #If updates are manually paused
        txtrect = renderText("Updates Off",10,80,(230,120,20),"Scanning has been manually disabled.",True,str(len(linked)) + " Linked Networks" if len(linked)>1 else "Single Network" if len(linked)!=0 else str(len(set(nameList))) + " - " + str(knownNetworks) + "/" + str(len(nDic)))
    elif len(nDic)>0 and iLst[5]==-1: #If there are networks around, but Wifi is off
        txtrect = renderText("Updates Disabled",10,80,(190,190,20),"WiFi is disabled.",True,str(len(linked)) + " Linked Networks" if len(linked)>1 else "Single Network" if len(linked)!=0 else str(len(set(nameList))) + " - " + str(knownNetworks) + "/" + str(len(nDic)))
    elif iLst[5]==-1 and len(nDic)==0: #If Wifi is off and no scan has occured yet
        txtrect = renderText("Scan Disabled",10,80,(240,120,120),"WiFi is disabled.")
    else:
        if len(nDic)==0: #If Wifi is on, but its still completeing the scan function
            txtrect = renderText("Searching." if counter%18<6 else "Searching.." if counter%18<12 else "Searching...",10,80,(160,160,160),"Scanning networks around you...")
        else:
            txtrect = renderText("Scan Active", 10,80,(110,245,20),"Scanning is active!",True,str(len(linked)) + " Linked Networks" if len(linked)>1 else "Single Network" if len(linked)!=0 else str(len(set(nameList))) + " - " + str(knownNetworks) + "/" + str(len(nDic)))
    if txtrect.inflate(0,-2).collidepoint(pg.mouse.get_pos()) and pg.mouse.get_pressed()[0] and not stopClick and len(nDic)>0:
        updatesPaused = not updatesPaused
        stopClick = True
    if phyMode!='':
        if phyMode=="802.11":
            if iLst[5]==-1:
                renderText("Not connected", bat,HEI-55,colSet,"PHY only avaliable when connected.")
            else:
                renderText("Still Finding PHY...", bat,HEI-55,colSet,"Got an invalid result from the PHY search. Trying again...")
        else:
            renderText(phyMode, bat,HEI-55,colSet,"Current PHY Mode of your network. (WiFi Generation)",True,"Wifi " + str(1+gens.index(phyMode[6:])))
    else:
        if iLst[7]==-1:
            renderText("Not Connected", bat,HEI-55,(180,180,180),"PHY only avaliable when connected.")
        else:
            try:
                renderText("802.11" + str(gens[probGen]), bat,HEI-55,colSet,"Guessing PHY mode based on max speed.",True,"Probably Wifi " + str(1+probGen))
            except:
                renderText("Finding PHY Mode...", bat,HEI-55,(230,230,230),"Finding PHY Mode...")
    if avgTxr!=0:
        pg.draw.line(screen, colSet, (bat,HEI-24), ((int(math.log10(avgTxr/1.2)*(wit/3)+bat), HEI-24)), 2)
        pg.draw.line(screen, (80,80,80), ((int(math.log10(maxSpd/1.2)*(wit/3)+bat), HEI-24)), (WID-30,HEI-24), 2)
        colSet = tuple(round(ti/1.333) for ti in colSet)
        pg.draw.line(screen, colSet, (int(math.log10(maxSpd/1.2)*(wit/3)+bat), HEI-14), (int(math.log10(maxSpd/1.2)*(wit/3)+bat), HEI-34), 2)
        colSet = tuple(round(ti/min(1.333,max(1,((maxSpd/avgTxr)/2)))) for ti in colSet)
        pg.draw.line(screen, colSet, (int(math.log10(avgTxr/1.2)*(wit/3)+bat), HEI-24), (int(math.log10(maxSpd/1.2)*(wit/3)+bat), HEI-24), 2)
        renderText(str(round(avgTxr)) + "/" + str(maxSpd) + "Mb/s", bat,HEI-75,(230,230,230),"Current and max speed of your network.")
        pg.draw.circle(screen, (230,230,230), (int(math.log10(avgTxr/1.2)*(wit/3)+bat), HEI-23), 8)
        if (upSpd+downSpd)/1024/1024>1.2:
            avgSpd = (upSpd+downSpd)/1024/1024
            pg.draw.line(screen, (230,230,230),(int(math.log10(avgSpd/1.2)*(wit/3)+bat),HEI-14),(int(math.log10(avgSpd/1.2)*(wit/3)+bat),HEI-34),2)
    else:
        pg.draw.line(screen, (80,80,80), (bat,HEI-24), (WID-30,HEI-24), 2)
    pg.draw.line(screen, (200,200,200), (WID-30,HEI-34), (WID-30,HEI-14), 2)
    pg.draw.line(screen, (140,140,140), (bat+round(2*wit/3),HEI-34), (bat+round(2*wit/3),HEI-14),2)
    pg.draw.line(screen, (140,140,140), (bat+round(wit/3),HEI-34), (bat+round(wit/3),HEI-14),2)
    pg.draw.line(screen, (200,200,200), (bat,HEI-34), (bat,HEI-14), 2)
#Lines--------------------------------------------------------------------------
    pg.draw.line(screen, (200,200,200), (15,26), (15,56), 2)
    pg.draw.line(screen, (200,200,200), (WID-40,26), (WID-40,56), 2)
    pg.draw.line(screen, (180,40,40), (15+10*((WID-55)/95),31), (15+10*((WID-55)/95),51), 2) #-95 cutoff
    pg.draw.line(screen, (180,180,40), (15+25*((WID-55)/95),31), (15+25*((WID-55)/95),51), 2) #-80 acceptable signal
    pg.draw.line(screen, (40,180,40), (15+35*((WID-55)/95),31), (15+35*((WID-55)/95),51), 2) #-70 reliable signal
    pg.draw.line(screen, (140,140,140), (15+45*((WID-55)/95),31), (15+45*((WID-55)/95),51), 2)
    pg.draw.line(screen, (140,140,140), (15+55*((WID-55)/95),31), (15+55*((WID-55)/95),51), 2)
    pg.draw.line(screen, (140,140,140), (15+65*((WID-55)/95),31), (15+65*((WID-55)/95),51), 2)
    pg.draw.line(screen, (150,150,150), (15+75*((WID-55)/95),31), (15+75*((WID-55)/95),51), 2)
    pg.draw.line(screen, (160,160,160), (15+85*((WID-55)/95),31), (15+85*((WID-55)/95),51), 2)
    pg.draw.line(screen, (200,200,200), (15,HEI-34), (15,HEI-14),2)
    pg.draw.line(screen, (200,200,200), (ba5+wi5,HEI-34), (ba5+wi5,HEI-14),2)
    pg.draw.line(screen, (200,200,200), (65+wi2,HEI-34), (65+wi2,HEI-14),2)
    pg.draw.line(screen, (200,200,200), (15+wi2,HEI-34), (15+wi2,HEI-14),2)
    if pg.mouse.get_pressed()[2]:
        renderText('-10',WID-55,61,tuple(i+max(0,180-(dFromPt(WID-55,61)*3)) for i in bgColor))
#Finishing Up--------------------------------------------------------------------------
    endTimer = process_time()
    if not pg.key.get_focused():
        fpss = [8,20,30]
        targetFps=fpss[fpsSetting]
    else:
        if fpsSetting==0:
            targetFps = round(15+min(15,abs(rememberRssi-averageRssi)*250))
        else:
            targetFps = 30*fpsSetting
    hovNum = ''
    frameTime = endTimer-startTimer
    rememberRssi = averageRssi
    fpsList.pop(-1)
    fpsList.insert(0,frameTime)
    fTimeSec = 1/(sum(fpsList)/len(fpsList))
    txtrect = renderText(str(targetFps),10,100,(230,120,20) if fpsSetting==0 else (230,230,230) if fpsSetting==1 else (80,240,160),"Target FPS. Click to cycle through FPS settings.")
    if txtrect.inflate(0,-2).collidepoint(pg.mouse.get_pos()) and pg.mouse.get_pressed()[0] and not stopClick:
        fpsSetting+=1
        if fpsSetting==3:
            fpsSetting = 0
        stopClick = True
    if iLFrame>0:
        pg.draw.circle(screen, (iLFrame*53+40,iLFrame*53+40,40) if gotPhy else (iLFrame*53+40,40,40),(35,108),4)
        iLFrame-=1
    if spFrame>0:
        pg.draw.circle(screen, (40,40+spFrame*53,40),(bat+5+textLength(str(round(avgTxr)) + "/" + str(maxSpd) + "Mb/s"),HEI-67),4)
        spFrame-=1
    if scFrame>0:
        scFrame-=0.5
    nl = str(round(targetFps/fTimeSec*100,1)) + "%"
    txtrect = renderText(str(nl),40,100,(230,120,20) if updateSpeed==0 else (230,230,230) if updateSpeed==1 else (80,240,160),"CPU Usage. Click to cycle through update speeds.",True,str(round(fTimeSec)) + " FPS")
    if txtrect.inflate(0,-2).collidepoint(pg.mouse.get_pos()) and pg.mouse.get_pressed()[0] and not stopClick:
        updateSpeed+=1
        if updateSpeed==3:
            updateSpeed=0
        stopClick = True
    if not pg.mouse.get_pressed()[0]:
        stopClick = False
    WID, HEI = pg.display.get_window_size()
    if remWidth!=WID or remHeight!=HEI:
        renderFrame = True
    remWidth=WID
    remHeight=HEI
    sleep(max(0,(1/targetFps)-frameTime))
    counter+=1
    if (iLst[4]=="None") or storeSsid!=iLst[4]:
        counter=0
        phyMode = ''
        makeNewLists()
    storeSsid = iLst[4]
    renderText("a0.45", WID-40,5, tuple(i+max(0,180-(dFromPt(WID-40,5)*3)) for i in bgColor),"Version Alpha 0.45 - (Feb 21st 2023)", False)
    if pg.mouse.get_pos()[0]>WID-43 and pg.mouse.get_pos()[1]<20 and pg.mouse.get_pressed()[0]:
        os.system("open https://jswessler.carrd.co/")
    pg.display.flip()
