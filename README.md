Daemon that creates two file handles that can be used to transfer data through wifi interfaces without connection between them.

How this work. App:

1. Set monitor mode on interface.
2. Switch to desired frequency ( default channel 5).
3. Create fifo file named rtx-send to with we can write to send data.
4. Create fifo file named rtx-recive from with we can get the data from another device that runs this software.

