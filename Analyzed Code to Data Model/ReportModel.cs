using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

public class Report
{
    public List<Vuln> Vulns;

    public Report()
    {
        Vulns = new();
    }
}
public class Vuln
{
    public GeneralData GeneralData { get; set; }
    public InitialState InitialState { get; set; }
    public Account Account { get; set; }
    public List<Transaction> Transactions;

    public Vuln()
    {
        GeneralData = new GeneralData();
        InitialState = new InitialState();
        Account = new Account();
        Transactions = new();
    }
    public override String ToString()
    {
        string trans ="";
        foreach(Transaction tran in Transactions)
        {
            trans += tran.ToString() + "\n";
        }
        return GeneralData.ToString() + InitialState.ToString() + $"---Transaction---\n" + trans;
    }
}

public class GeneralData
{
    public string? FaultName { get; set; }
    public int? SwcId { get; set; }
    public string? Severity { get; set; }
    public string? Contract { get; set; }
    public string? FunctionName { get; set; }
    public int? PcAddress { get; set; }

    //TODO legyen-e int tömb
    public string? EstimatedGasUsage { get; set; }
    public string? Description { get; set; }
    public string? File { get; set; }

    //maybe redundant
    public string? Code { get; set; }
    public override String ToString()
    {
        return 
            $"---General Data---\n" +
            $"Fault Name: {FaultName}\n" +
            $"SWC ID: {SwcId}\n" +
            $"Severity: {Severity}\n" +
            $"Contract: {Contract}\n" +
            $"Function Name: {FunctionName}\n" +
            $"PC Address: {PcAddress}\n" +
            $"Estimated Gas Usage: {EstimatedGasUsage}\n" +
            $"Description: {Description}\n\n" +
            $"File: {File}\n" +
            $"Code: {Code}\n\n";
    }
}

public class InitialState
{
    public InitialState()
    {
        Creator = new Account();
        Attacker = new Account();
    }
    public Account Creator { get; set; }
    public Account Attacker { get; set; }
    public override String ToString()
    {
        return "---Initial State---\n" + Creator.ToString() + "\n" + Attacker.ToString() +"\n";
    }
}

public class Account
{
    public string? Name { get; set; }
    public string? Balance { get; set; }
    public int? Nonce { get; set; }
    public string? Storage { get; set; }
    public override String ToString()
    {
        return $"Name: {Name}\n" +
               $"Balance: {Balance}\n" +
               $"Nonce: {Nonce}\n" +
               $"Storage: {Storage}\n";
    }
}

public class Transaction
{
    public string? Caller { get; set; }
    public string? Function { get; set; }
    public string? TxData { get; set; }
    //TODO: make toString for this
    public string[]? DecodedData { get; set; }
    public string? Value { get; set; }
    public override String ToString()
    {
        string decoded = "";
        foreach (string data in DecodedData!)
        {
            decoded += data.ToString() + "\n";
        }
        return $"Caller: {Caller}\n" +
               $"Function: {Function}\n" +
               $"txData: {TxData}\n" +
               $"DecodedData: {decoded}" +
               $"Value: {Value}\n";
    }
}
