import PySimpleGUI as sg
def progress():
    for i in range(1000):
        sg.OneLineProgressMeter('Processing', i+1, 1000, 'mymeter')


api = '62c4e8fc4ddc02a74ddd5e60f1bc0bb5596d005aa661322caf634ba21bcdf54c'   
sg.theme('Dark Black')
layout = [
    [sg.Text('File Analyser',font=("Helvetica", 30))],
    [sg.Checkbox('Hash', size=(10,1)),sg.Checkbox('File', size=(10,1)),sg.Checkbox('URL', size=(10,1)),sg.Checkbox('PcapFile', size=(10,1))], #0,1,2,3
    [sg.Text('Choose a file', size=(10, 1)), sg.Input(), sg.FileBrowse()], #4
    [sg.Text('Enter output file name', size=(10, 1)), sg.Input(), sg.FileBrowse()], #5
    [sg.Submit(), sg.Cancel()],
    [sg.Text('_'  * 100, size=(65, 1))],
    #[sg.Text('Check for infected files',font=("Helvetica", 10)),sg.Checkbox('Yes', size=(10,1))],
]
window = sg.Window('File Analyser', layout)
event, values = window.read()
window.close()
print(values[0],values[1])
c=0
if(values[0] == True):
	import vtcheck
	vtcheck.VT_Request(api,values[4],values[5])
	progress()
	sg.popup("Success")

elif(values[1]==True):
	import vtcheck
	vtcheck.VT_Request(api, vtcheck.VT_file(values[4]),values[5])
	progress()
	sg.popup("Success")
elif(values[2]==True):
	import vtcheck
	vtcheck.url(api,values[4],values[5])
	progress()
	sg.popup("Success")

elif(values[3]==True):
	import pcapextract
	import vtcheck
	
	pcapextract.stripurl_pcap(values[4], values[5])
	print("!")
	file= values[5]
	lines=[]
	with open(file) as f:
		lines = f.readlines()

	for i in range(len(lines)):
		vtcheck.url(api,lines[i],'report.txt')
	progress()
	sg.popup("Success")
else:
	sg.popup("Select atleast one option")


