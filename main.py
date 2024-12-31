# on-board goodies
import sys
import os
import gc
import uasyncio
from hashlib import sha1
import urequests as requests
from time import sleep, gmtime, localtime
import network
import ntptime
from machine import Pin, I2C, PWM, reset

sys.path.append("/include")
# external things
from machine_i2c_lcd import I2cLcd
import hmac
import base64
import md5
import io
import socket
import select

# Global variables so it can be persistent
solar_usage = {}
led_bright = 800
CRED_FILE = "config/credentials.env"

# Device descriptors
# define the display
# WEMOS LOLIN32 ESP32 Lite pinout
sdaPIN = Pin(23)
sclPIN = Pin(19)
# S2MINI pinout (I think)
# sdaPIN = Pin(33)
# sclPIN = Pin(35)
i2c = I2C(0, sda=sdaPIN, scl=sclPIN, freq=400000)
devices = i2c.scan()
for device in devices:
    print("i2c address is" + hex(device))
I2C_ADDR = 0x27
I2C_NUM_ROWS = 2
I2C_NUM_COLS = 16
lcd = I2cLcd(i2c, I2C_ADDR, I2C_NUM_ROWS, I2C_NUM_COLS)
led_out = PWM(Pin(5), freq=500, duty=800)
# Usage: led_out.init(freq=500, duty=led_bright)
led_btn = Pin(34, Pin.IN, Pin.PULL_UP)
day_btn = Pin(35, Pin.IN, Pin.PULL_UP)
reset_btn = Pin(36, Pin.IN, Pin.PULL_UP)


# Local time doings
def stringTime(thisTime):
    year, month, date, hour, minute, second, week_day, year_day = thisTime
    week_day_lookup = b"MonTueWedThuFriSatSun"
    month_lookup = b"JanFebMarAprMayJunJulAugSepOctNovDec"
    stringTime = (
        week_day_lookup.decode()[week_day * 3 : week_day * 3 + 3]
        + ", "
        + f"{date:02}"
        + " "
        + month_lookup.decode()[(month - 1) * 3 : (month - 1) * 3 + 3]
        + " "
        + f"{year:02}"
        + " "
        + f"{hour:02}"
        + ":"
        + f"{minute:02}"
        + ":"
        + f"{second:02}"
        + " GMT"
    )
    return stringTime

# returns a string representation of a floating point
# number (expressed as a string) rounded to specified precision
# (default 1)
def roundStr(float_str,ndigits=1):
    try:
        f = round(float(float_str),ndigits)
        return str(f)        
    except ValueError:
        return "0.0" ;
    
def getSolis(sfd):
    solar_dict = {}

    solar_text = ""
    solar_resp = "!!!"
    try:
        gc.collect()
        gc.threshold(gc.mem_free() // 4 + gc.mem_alloc())

        # wait for new data to arrive - up to 30s
        rdescriptors = []
        wdescriptors = []
        xdescriptors = []
        rdescriptors.append(sfd)
        ready_set = select.select(rdescriptors,wdescriptors,xdescriptors,30)
        # bail if nothing arrived, this triggers the 'no data returned' condition
        # which would originally occur in the event of a comms failure to the Solis cloud
        if len(ready_set[0])==0:
            return solar_dict
        
        packet, address = sfd.recvfrom(9000)
        solar_text = str(packet,'utf-8')
        solar_resp = 500
    except Exception as e:
        print("get solar_usage didn't work sorry because this: " + str(e))

    solar_dict = {"resp": solar_resp}

    if solar_text != "":
        for each_field in solar_text.split(","):
            if '"dataTimestamp":' in each_field:
                dataTimestamp = each_field.split(":")[1]
                solar_dict["timestamp"] = dataTimestamp.replace('"', "")
            if '"pac":' in each_field:
                solar_dict["solar_in"] = roundStr(each_field.split(":")[1])
            if '"batteryCapacitySoc":' in each_field:
                solar_dict["battery_per"] = each_field.split(":")[1]
            if '"psum":' in each_field:
                solar_dict["grid_in"] = roundStr(each_field.split(":")[1])
            if '"familyLoadPower":' in each_field:
                solar_dict["power_used"] = roundStr(each_field.split(":")[1])
            if '"eToday":' in each_field:
                solar_dict["solar_today"] = roundStr(each_field.split(":")[1])
    return solar_dict


def lcd_line(lcd, lcd_string, row=0, col=0):
    if row == 0 and col == 0:  # presume we want to clear the screen if it's top left
        lcd.clear()
    lcd.move_to(col, row)
    lcd.putstr(lcd_string)


# Coroutine: get the solis data every 45 seconds
def display_data(solar_usage, lcd, force=False):
    # do something funny with the battery icon ha
    battery_icon = bytearray([0x0E, 0x0E, 0x11, 0x1F, 0x1F, 0x1F, 0x1F, 0x1F])
    battery_int = int(float(solar_usage["battery_per"]))
    grid_float = float(solar_usage["grid_in"])
    # Sanity check printing business
    print("solis timestamp is: " + solar_usage["timestamp"])
    print("solar_in is: " + solar_usage["solar_in"])
    print("battery_per is: " + solar_usage["battery_per"])
    print("grid_in is: " + solar_usage["grid_in"])
    print("power_used is: " + solar_usage["power_used"])
    print("solar_today is: " + solar_usage["solar_today"] + "\n")
    if force or (int(solar_usage["timestamp"]) > int(solar_usage["prev_timestamp"])):
        print("Solis data has been updated - do the LCD thing...")
        # LCD business
        if battery_int < 90:
            battery_icon[1] = 0x0A
        if battery_int < 75:
            battery_icon[2] = 0x11
        if battery_int < 60:
            battery_icon[3] = 0x11
        if battery_int < 45:
            battery_icon[4] = 0x11
        if battery_int < 30:
            battery_icon[5] = 0x11
        if battery_int < 15:
            battery_icon[6] = 0x11
        lcd.custom_char(5, battery_icon)
        lcd.clear()
        # Solar
        lcd.putstr(chr(0) + " " + solar_usage["solar_in"][:4] + "kW      ")
        # Battery
        lcd.move_to(9, 0)
        lcd.putstr(chr(5))
        if battery_int == solar_usage["prev_battery_int"]:
            lcd.putstr("=")
        if battery_int < solar_usage["prev_battery_int"]:
            lcd.putstr(chr(4))
        if battery_int > solar_usage["prev_battery_int"]:
            lcd.putstr(chr(3))
        lcd.putstr(" " + str(battery_int) + "%     ")
        # Grid
        lcd.move_to(0, 1)
        lcd.putstr(chr(1))
        if grid_float == 0:
            lcd.putstr("=0kW   ")
        if grid_float < 0:
            lcd.putstr(chr(4) + solar_usage["grid_in"][1:5] + "kW    ")
        if grid_float > 0:
            lcd.putstr(chr(3) + solar_usage["grid_in"][:4] + "kW    ")
        # Usage
        lcd.move_to(9, 1)
        lcd.putstr(
            chr(2)
            + solar_usage["power_used"][:4]
            + "kW"
            + " " * (4 - len(solar_usage["power_used"][:4]))
        )
    else:
        print("old data, discarding")


async def timer_solis_data(lcd):
    global solar_usage
    solar_usage["prev_battery_int"] = 0
    solar_usage["prev_timestamp"] = "0"

    # create socket to listen for the broadcast packets
    # sent periodically by the solar app
    print("Creating UDP socket for listen")
    solar_sfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    solar_sfd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_address = ('0.0.0.0',52005)
    solar_sfd.bind(listen_address)

    while True:
        #lcd_line(lcd, chr(6), 1, 8)
        solar_dict = getSolis(solar_sfd)
        if "timestamp" in solar_dict:
            lcd_line(lcd, " ", 1, 8)
            solar_usage.update(solar_dict)
            display_data(solar_usage, lcd)
            # ready to loop then
            solar_usage["prev_battery_int"] = int(float(solar_usage["battery_per"]))
            solar_usage["prev_timestamp"] = solar_usage["timestamp"]
        else:
            lcd_line(lcd, chr(7), 1, 8)
            print("No data returned")
            if "resp" in solar_dict:
                solar_usage["resp"] = solar_dict["resp"]


async def wait_brightness():
    global led_bright
    while True:
        led_out.duty(led_bright)
        await uasyncio.sleep_ms(100)


# Coroutine: reset button
async def wait_reset_button():
    global CRED_FILE
    btn_count = 0
    btn_max = 75
    while True:
        if reset_btn.value() == 1:
            btn_count = 0
        if reset_btn.value() == 0:
            print(f"Pressed - count is {str(btn_count)}")
            btn_count = btn_count + 1
        if btn_count >= btn_max:
            lcd_line(lcd, "Full reset")
            sleep(2)
            os.remove(CRED_FILE)
            reset()
        await uasyncio.sleep(0.04)


# Coroutine: led button
async def wait_led_button():
    global led_bright
    prev_btn = 1
    while True:
        if led_btn.value() == 1 and prev_btn == 0:
            led_bright = (led_bright + 200) % 1200
        prev_btn = led_btn.value()
        await uasyncio.sleep(0.04)


# Coroutine: day button press
async def wait_day_button(day_btn):
    btn_prev = day_btn.value()
    while (day_btn.value() == 1) or (day_btn.value() == btn_prev):
        btn_prev = day_btn.value()
        await uasyncio.sleep(0.04)


# Corouteine: display solar today
async def display_solar_today(lcd):
    if "solar_today" in solar_usage:
        print("Solar today is " + solar_usage["solar_today"])
        print("Last updated: " + solar_usage["timestamp"])
        lcd_line(lcd, "Today: " + solar_usage["solar_today"][:4] + "kW")
        solis_time = stringTime(
            localtime(int(float(solar_usage["timestamp"]) / 1000))
        )[-12:].replace("GMT", "UTC")
        lcd_line(lcd, "at " + solis_time, 1)
    else:
        if "resp" in solar_usage:
            print("No Solar today data - oops")
            print(f"last response code: {solar_usage['resp']}")
            lcd_line(lcd, "solis response:")
            lcd_line(lcd, str(solar_usage["resp"]), 1)
    await uasyncio.sleep(5)
    # put the old data back
    if "timestamp" in solar_usage:
        display_data(solar_usage, lcd, True)
    print("And I'm done.")


async def main():
    global led_bright
    led_out.init(freq=500, duty=led_bright)

    # Custom character bits
    solar_icon = bytearray([0x00, 0x15, 0x0E, 0x1F, 0x1F, 0x0E, 0x15, 0x00])
    lcd.custom_char(0, solar_icon)
    grid_icon = bytearray([0x07, 0x0E, 0x18, 0x1F, 0x07, 0x0E, 0x0C, 0x10])
    lcd.custom_char(1, grid_icon)
    mains_icon = bytearray([0x00, 0x0A, 0x0A, 0x1F, 0x1F, 0x0E, 0x04, 0x1C])
    lcd.custom_char(2, mains_icon)
    up_icon = bytearray([0x04, 0x0E, 0x1B, 0x11, 0x00, 0x00, 0x00, 0x00])
    lcd.custom_char(3, up_icon)
    down_icon = bytearray([0x00, 0x00, 0x00, 0x00, 0x11, 0x1B, 0x0E, 0x04])
    lcd.custom_char(4, down_icon)
    try_dot = bytearray([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04])
    lcd.custom_char(6, try_dot)
    bad_dot = bytearray([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A])
    lcd.custom_char(7, bad_dot)

    solisInfo = {}
    # Now separate credentials
    global CRED_FILE
 
    try:
        with open(CRED_FILE, "rb") as f:
            contents = f.read().split(b",")
            if len(contents) == 6:
                (
                    solisInfo["wifiSSID"],
                    solisInfo["wifiPass"],
                    solisInfo["solisKey"],
                    solisInfo["solisSecret"],
                    solisInfo["solisId"],
                    solisInfo["solisSn"],
                ) = contents
    except OSError:
        print("No or invalid credentials file - please reset and start again")
        sys.exit()

    f = open("config/solis.env")
    for line in f:
        if "=" in line:
            thisAttr = line.strip().split("=")[0]
            thisVal = line.strip().split("=")[1]
            solisInfo[thisAttr] = thisVal
    f.close()

    # Initial display goodness
    lcd.clear()
    lcd.hide_cursor()
    lcd_line(lcd, "Starting up...")
    sleep(2)

    # Configure the network
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    print("Connecting", end="")
    lcd_line(lcd, "Connecting to")
    lcd_line(lcd, "WiFi ...", 1)
    wlan.connect(solisInfo["wifiSSID"], solisInfo["wifiPass"])
    ipAddress, netMask, defaultGateway, DNS = wlan.ifconfig()
    wifiCount = 0
    while ipAddress == "0.0.0.0" and wifiCount < 30:
        print(".", end="")
        sleep(1)
        ipAddress, netMask, defaultGateway, DNS = wlan.ifconfig()
        wifiCount += 1

    if ipAddress == "0.0.0.0":
        print("No WiFi connection - please check details in solis.env")
        sys.exit()

    print("Wifi connected - IP address is: " + ipAddress)
    lcd_line(lcd, "Connected. SSID:")
    lcd_line(lcd, solisInfo["wifiSSID"].decode(), 1)
    sleep(2)
    lcd_line(lcd, "Connected. IP:")
    lcd_line(lcd, ipAddress, 1)
    sleep(2)
    lcd_line(lcd, "Getting data ...")

    ntptime.host = "0.uk.pool.ntp.org"
    ntptime.settime()

    # Main loop
    # Get the solis data

    uasyncio.create_task(timer_solis_data(lcd))
    uasyncio.create_task(wait_brightness())
    uasyncio.create_task(wait_led_button())
    uasyncio.create_task(wait_reset_button())

    while True:
        await wait_day_button(day_btn)
        await display_solar_today(lcd)


if __name__ == "__main__":
    try:
        # Start event loop and run entry point coroutine
        uasyncio.run(main())
    except KeyboardInterrupt:
        pass
