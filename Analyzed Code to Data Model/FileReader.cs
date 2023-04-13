using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection.Metadata;
using System.Text;
using System.Threading.Tasks;

public class FileReader
{
    string[] fileLines;
    Report report;
    Vuln vuln;

    //count empty lines cuz not always 26
    int lineCnt = 0;
    public FileReader(string path){
        fileLines = System.IO.File.ReadAllLines(path);
        report = new Report();
        vuln = new Vuln();
    }
    public Report readAndParse()
    {
        foreach (string line in fileLines){
            if (lineCnt <= 12)
            {
                loadGeneralData(line);
            }
            if(lineCnt >= 13 && lineCnt <= 18)
            {
                loadInitialState(line);
            }
            if (lineCnt >= 23) //until üres sor
            {
                loadTransaction(line);
            }
            lineCnt++;
            //loadTransaction(vuln, line);
            //report.Vulns.Add(vuln);
        }
        //Console.WriteLine(vuln.ToString());
        return report;
    }
    public void loadGeneralData(string line)
    {
        string[] parts = line.Split(":");
        string key = parts[0].Trim();
        string value = "null";
        if (parts.Length > 1)
        {
           value = parts[1].Trim();
        }
        switch (lineCnt){
            case 0:
                vuln.GeneralData.FaultName = line.Replace("=", "").Trim();
                break;
            case 1:
                vuln.GeneralData.SwcId = int.Parse(value);
                break;
            case 2:
                vuln.GeneralData.Severity = value;
                break;
            case 3:
                vuln.GeneralData.Contract = value;
                break;
            case 4:
                vuln.GeneralData.FunctionName = value;
                break;
            case 5:
                vuln.GeneralData.PcAddress = int.Parse(value);
                break;
            case 6:
                vuln.GeneralData.EstimatedGasUsage = value;
                break;
            case 7:
                vuln.GeneralData.Description = line.Trim();
                break;
            case 8:
                vuln.GeneralData.Description +=" " + line.Trim();
                break;
            case 10:
                vuln.GeneralData.File = value +":"+ parts[2];
                break;
            case 12:
                vuln.GeneralData.Code = line;
                break;
            default:
                    break;
            }
    }
    private void loadInitialState(string line){
        string[] parts = line.Split(",");
        string balance = "";
        int nonce = 0;
        string storage = "";
        if (parts.Length > 2)
        {
            string[] balanceLine = parts[1].Split(":");
            string[] nonceLine = parts[2].Split(":");
            string[] storageLine = parts[3].Split(":");
            balance = balanceLine[1].Trim();
            nonce = int.Parse(nonceLine[1].Trim());
            storage = storageLine[1].Trim();
        }
        switch (lineCnt)
        {
            case 17:
                //make creator
                vuln.InitialState.Creator.Name = "Creator";
                vuln.InitialState.Creator.Balance = balance;
                vuln.InitialState.Creator.Nonce = nonce;
                vuln.InitialState.Creator.Storage = storage;
                break;
            case 18:
                //make attacker
                vuln.InitialState.Attacker.Name = "Attacker";
                vuln.InitialState.Attacker.Balance = balance;
                vuln.InitialState.Attacker.Nonce = nonce;
                vuln.InitialState.Attacker.Storage = storage;
                break;
            default:
                break;
        }
    }
    public void loadTransaction(string line){
        string[] parts = line.Split(",");
        if(parts.Length > 4)
        {
            string[] callerLine = parts[0].Split(":");
            string[] functionLine = parts[1].Split(":");
            string[] txDataLine = parts[2].Split(":");
            string[] decodedDataLine = parts[3].Split(":"); //itt még elválasztva van egy rakat sor a value előtt
            string[] valueLine = parts[parts.Length - 1].Split(":");
            Console.WriteLine(callerLine[1]);
            Console.WriteLine(functionLine[1]);
            Console.WriteLine(txDataLine[1]);
            Console.WriteLine(decodedDataLine[1]);
            Console.WriteLine(valueLine[1]);
        }

        foreach (string part in parts)
        {
            //Console.WriteLine(part);
        }
    }
}

/**
 * 0. Read Title
 * 1-6 Kettőspontos részek
 * 7 rövid leírás
 * 8 hosszú leírás
 * 9 üres
 * 10 Melyik file
 * 11 Üres
 * 12 Melyik hívás
 * 13 üres
 * 14 Üres
 * 15 Initial state cím
 * 16 Üres
 * 17-18 Accounts
 * 19 üres
 * 20 Transaction sequence cím
 * 21 Üres
 * 22-until ures sor Fv Hívások megadása
 * 
 * 
 * switch (lineCnt){
                case 0:
                    vuln.GeneralData.FaultName = line;
                    break;
                case >=1 and <= 14:
                    string[] parts = line.Split(":");
                    string key = parts[0].Trim();
                    string value = parts[1].Trim();

                    switch (key)
                    {
                        case "SWC ID":
                            vuln.GeneralData.SwcId = int.Parse(value);
                            break;
                        case "Severity":
                            vuln.GeneralData.Severity = value;
                            break;
                        case "Contract":
                            vuln.GeneralData.Contract = value;
                            break;
                        case "Function name":
                            vuln.GeneralData.FunctionName = value;
                            break;
                        case "PC address":
                            vuln.GeneralData.PcAddress = int.Parse(value);
                            break;
                        case "Estimated Gas Usage":
                            vuln.GeneralData.EstimatedGasUsage = value;
                            break;
                        case "Description":
                            vuln.GeneralData.Description = value;
                            break;
                        case "In file":
                            vuln.GeneralData.File = value;
                            break;
                        case "":
                            break;
                        default:
                            break;
                    }
                    break;
                default:
                    break;
            }
 */