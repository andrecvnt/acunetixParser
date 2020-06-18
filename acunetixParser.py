#!/usr/bin/env python
import xml.etree.ElementTree as ET
import csv
import os

print('##################################')
print('####                          ####')
print("####     ACUNETIX PARSER      ####")
print('#### developed by andrecvnt   ####')
print('####                          ####')
print('##################################\n')

## FAZ O PARSE
def xmlToCSV(file):
	## LE O XML
	tree = ET.parse(file)
	root = tree.getroot()

	for nomeDaVuln in root.iter('Scan'):

		for cadaItem in nomeDaVuln.iter('ReportItem'):

			## IGNORA AS VULNERABILIDADES DE SEVERIDADE 'INFO'
			if cadaItem.find('Severity').text == 'informational':
				break

			## CRIA LINHAS DO CSV
			linhaDoCSV = []
			StartURL = nomeDaVuln.find('StartURL').text
			Name = cadaItem.find('Name').text
			Affects = cadaItem.find('Affects').text
			Parameter = cadaItem.find('Parameter').text
			Severity = cadaItem.find('Severity').text
			Impact = cadaItem.find('Impact').text
			Description = cadaItem.find('Description').text
			Recommendation = cadaItem.find('Recommendation').text
			TechnicalDetails = cadaItem.find('TechnicalDetails').text
			if cadaItem[15][0].text is None:
				TechnicalDetails = cadaItem[15][0].text
			else:
				TechnicalDetails = cadaItem[15][0].text.encode('utf-8')
			if cadaItem[15][0].text is None:
				Method = cadaItem[15][0].text
			else:
				Method = cadaItem[15][0].text.encode('utf-8').partition(' ')[0]
			References = cadaItem.find('References').text
			FinishTime = nomeDaVuln.find('FinishTime').text
			Os = nomeDaVuln.find('Os').text
			WebServer = nomeDaVuln.find('WebServer').text

			## ADICIONA EM LISTA
			linhaDoCSV.append(StartURL)
			linhaDoCSV.append(Name)
			linhaDoCSV.append(Affects)
			linhaDoCSV.append(Parameter)
			linhaDoCSV.append(Severity)
			linhaDoCSV.append(Impact)
			linhaDoCSV.append(Description)
			linhaDoCSV.append(Recommendation)
			linhaDoCSV.append(TechnicalDetails)
			linhaDoCSV.append(Method)
			linhaDoCSV.append(References)
			linhaDoCSV.append(FinishTime)
			linhaDoCSV.append(Os)
			linhaDoCSV.append(WebServer)

			## ESCREVE NO CSV
			csvwriter.writerow(linhaDoCSV)


## USAGE
print('UTILIZACAO: python acunetixparse.py')
print('Obs.: Os arquivos xmls devem estar no mesmo diretorio do script com a extensao xml.\n')

## VARIAVEIS
print('Criando lista de headers do CSV...')
headerDoCSV = ['url','Name','Affects','Parameter','Severity','Impact','Description','Recommendation','TechnicalDetails','Method','References','FinishTime','Os','WebServer']
cwd = os.getcwd()

## INICIA HEADER DO CSV
print('Criando arquivo MatrizDeVulnerabilidades.xls..\n')
MatrizDeVulnerabilidades = open('MatrizDeVulnerabilidades.xls', 'wb')
csvwriter = csv.writer(MatrizDeVulnerabilidades, delimiter='\t')
csvwriter.writerow(headerDoCSV)


for filename in os.listdir(cwd):
	if not filename.endswith('.xml'): continue
	print('Realizando parse do arquivo: ' + filename)
	xmlToCSV(filename)

print("\nSALVANDO RESULTADOS EM..")
print(cwd +'MatrizDeVulnerabilidades.txt')
MatrizDeVulnerabilidades.close()
