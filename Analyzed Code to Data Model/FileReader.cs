using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
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

    int lineCnt = 0;
    int tranCnt = 0;
    bool endOfVuln = false;

    public FileReader(string path){
        fileLines = System.IO.File.ReadAllLines(path);
        report = new();
        vuln = new();    
    }

    public void readAndParse()
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
            if (lineCnt >= 23 && !endOfVuln)
            {
                loadTransaction(line);
            }
            lineCnt++;
            if (endOfVuln)
            {
                lineCnt = 0;
                endOfVuln = false;
                report.Vulns.Add(vuln);
                vuln = new Vuln();
            }
        }
        //Adds Last Vuln
        report.Vulns.Add(vuln);
        //Console.WriteLine(report.Vulns.Count);
        Console.WriteLine(report);
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
            //TODO Split parts[0] and assign name
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
        if(line.Equals(string.Empty))
        {
            endOfVuln = true;
        }
        string[] parts = line.Split(":");

        if(parts.Length > 4)
        {
            string[] callerLine = parts[1].Split(",");
            string[] functionLine = parts[2].Split(",");
            string[] txDataLine = parts[3].Split(",");
            string[] decodedDataLine = parts[4].Split(",");
            string caller = callerLine[0].Trim().Trim('[').Trim(']');
            string function = "";
            string txData = "";
            string decodedData = "";
            string value = parts[parts.Length-1].Trim();

            for(int i = 0; i < functionLine.Length-1; i++)
            {
                function += functionLine[i] +", ";
            }
            for(int i = 0; i < txDataLine.Length-1; i++)
            {
               txData += txDataLine[i] +", ";
            }
            for(int i = 0; i < decodedDataLine.Length-1; i++)//put these into string[]
            {
                if(decodedDataLine[i] != ")")
                {
                    decodedData += decodedDataLine[i].Trim().Trim('(').Trim(')').Trim('\'') +", ";
                }
            }
            
            Transaction tran = new Transaction();
            tran.Caller = caller;
            tran.Function = function.Trim().Trim(',');
            tran.TxData = txData.Trim().Trim(',');
            tran.DecodedData = decodedData.Trim().Trim(',');
            tran.Value = value;
            vuln.Transactions.Add(tran);
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
 */