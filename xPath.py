# -*-coding:utf-8-*-
"""
Usage: python xPath.py filename [-t]

Parse the special path tool. By default the result will be save as a excel file.

Example:
        xPath.py data.txt
"""

def usage():
	print __doc__

def split(dFilename):
	import re
	SEQ="/"
	re1 = re.compile(r"\[.*\]")
	re2 = re.compile(r"=.*")
	s1 = []
	try:
		data = open(dFilename, "r")
		try:
			s1 = data.readlines()
		finally:
			data.close()
	except:
		print "The [%s] file can not be opened." % dFilename

	result = []
	for t in s1:
		# ensure the correctly of data
		if (t == '\r\n'):
			continue
		if re.match('/.*?', t) == None:
			continue
		t = re.sub("\s", '', t)

		# handle special strings that like this '[xxxx]'
		if re.search('\[.*?\]', t) == None:
			# handle '"'
			if t.find('"') == 0:
				t = t.replace('"', '')
			elif t.find('"') == (len(t)-1):
				t = t.replace('"', '')

			i = 2
			cnt = t.count(SEQ)
			#print "cnt=%d, t=%s" % (cnt, t)
			while i <= cnt+1:
				s3 = SEQ.join(t.split(SEQ)[0:i])
				result.append(s3)
				i = i + 1
		else:
			s3_1 = re1.sub("", t)
			result.append(s3_1)

			# only handle '[xx=xx]' string, otherwise ignore it
			if re.search('\[.*?\]', t).group().find('=') > 0:
				s3_2 = re2.sub("", t).replace('[', '/')
				result.append(s3_2)

	result = list(set(result))
	#print result

	if len(sys.argv) == 3 and sys.argv[2] == '-t':
		# write result to one txt file
		filename = dFilename.split('.')[0]+'_new.txt'
		try:
			base = open(filename, "w")
			try:
				t = '\n'.join(result)
				base.writelines(t);
			finally:
				base.close()
		except:
			print "The [%s] file can not be opened." % filename 
	else:
		# write result to one excel file
		from pyExcelerator import Workbook
		filename = dFilename.split('.')[0]+'_new.xls'
		saveDatas(filename, result)
	print "Write all results to %s successful." % filename

def saveDatas(filename, datas):
	w = Workbook()
	ws = w.add_sheet('Results')
	
	count = 0
	for t in datas:
		ws.write(count, 0, t)
		count = count + 1
	w.save(filename)

def sort(bFilename, rslt):
	try:
		base = open(bFilename, "r")
		try:
			s2 = base.readlines()
		finally:
			base.close()
	except:
		print "The [%s] file can not be opened." % bFilename

	count = 0;
	for m in s2:
		if (m == '\r\n'):
			continue
		m = re.sub("\s", '', m)
		for n in rslt:
			if m == n:
				count = count+1
				print n
	print "Total: %d" % count

import sys, os
if __name__ == '__main__':
	if len(sys.argv) >= 2:
		datafile = sys.argv[1]
		#print 'The data file is %s \n' % (datafile)
		split(datafile)
	else:
		usage()
