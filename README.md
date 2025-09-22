# Covert Channel Attack on ChirpStack

## An example project in Go for a Covert Channel Attack to a LoRaWAN network with a ChirpStack Network Server

This project is a part of my Master thesis in Cybersecurity, it is an implementation of a Covert Channel Attack on a LoRaWAN network. I used a ChirpStack open source Network Server from Brocaar,
in particular the Dockerized version available in [ChirpStack Docker](https://github.com/chirpstack/chirpstack-docker?tab=readme-ov-file) and the [ChirpStack Simulator](https://github.com/brocaar/chirpstack-simulator)
project also from Brocaar to create the End Devices and the Gateway to test the attack.

### Instructions
My project runs on a Debian server and I will list the commands I used to install and setup everything I needed.
1. Download [GoLang](https://go.dev/dl/), then follow the instruction on how to [install](https://go.dev/doc/install) it

2. Pull this repository

3. Create a folder in which the project will run, for example `covert_channel_attack`

4. In the newly created folder pull two more repositories: [ChirpStack Docker](https://github.com/chirpstack/chirpstack-docker/tree/master) and [ChirpStack Simulator](https://github.com/brocaar/chirpstack-simulator)

5. Follow the instruction in ChirpStack Docker to setup the ChirpStack Network Server and lauch it in a terminal with
```
docker compose up
```
Then, open the ChirpStack web interface at http://localhost:8080/ and login with user: `admin` and psswd: `admin`.

6. Follow the instruction in ChirpStack Simulator to create the devices for the attack. After launching the command to create the configuration template file `chirpstack-simulator.toml`, copy and paste the example content in the repo in the file.

7. Change the number of devices to create in the simulation to a more reasonable number like 25 devices, the field is
```
# Number of devices to simulate.
  count=25
```
In the ChirpStack NS web interface, find the following information and insert it in the corresponding field of the `chirpstack-simulator.toml`file:
   - `tenant ID`: can be found in the homepage of the ChirpStack web interface, in the top half, just right next to the ChirpStack text.
   - `api key`: can be found in the "API Keys" menu, under the "Tenant" section on the left hand side of the page


8. Continue to follow instructions and launch the simulator, look at the log in the terminal and proceed the execution to the point where it creates the devices and then kill the process before it finishes the simulation. This step is important because if you let the simulation finish it will erase all created devices. To facilitate the creation of devices we exploit ChirpStack Simulator without actually usinig it.

9. Go inside `chirpstack-simulator/examples` directory and copy inside of it the`my_sender` folder, then go to `chirpstack-simulator/simulator` and substitute the file `device.go` with the one pulled from this repository.

10. Return in ChirpStack web interface and find 2 End Devices and 1  Gateway with the following relationship: one End Device has to refer to the chosen Gateway, while the other has to refer to another Gateway. To understand what are the correlation between the the devices, from the dashboard and under the "Tenant" menu go to `Applications -> <APPLICATION STRING> -> Devices`, here is the list of all EDs. From there, click on an ED DevEUI and go to the `LoRaWAN Frames` tab, in there you will find the Join Request and Join Accept messages exchanged between the device and the NS. Among other metadata it is also present the Gateway ID of the Gateway to which the ED refers to. Once you choose the couple (ED, Gateway), with the same procedure choose another ED that has a different Gateway associated to it. Now retrieve these informations:
    - The `gateway ID`
    - The `devEUI` and the `appKey` of ED linked to Gateway
    - The `devEUI` and the `appKey` of an ED not linked to the Gateway

11. In `chirpstack-simulator/examples/sender_00.go` find the variables `gatewayID`, `devEUI`, `appKey`, `devEUI_2` and `appKey_2`and insert there the corresponding values previously parsed from hex to int. To parse a value, for example, `appKey`, divide the string in pairs of charachter and feed them to a transformer online like [this](https://www.rapidtables.com/convert/number/hex-to-decimal.html) and then put every integer inside the curly brackets of the corresponding variable.

12. Open another terminal and move to:
```
cd chirpstack-simulator/examples/my_sender
```
compile with
```
go build
```
and execute the attack.


