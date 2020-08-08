# set terminal pngcairo
# set terminal png size 1920,1080
set logscale x 10 
plot '..\tftp-server\coverage.txt.graph' with lines
pause mouse close
