using System;
using System.Collections;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

//TODO ToString for all
public class Report
{
    public List<Vuln> Vulns { get; set; }
}
public class Vuln
{
    public Vuln()
    {
        GeneralData = new GeneralData();
        InitialState = new InitialState();
        Account = new Account();
        Transaction = new Transaction();
    }
    public GeneralData GeneralData { get; set; }
    public InitialState InitialState { get; set; }
    public Account Account { get; set; }
    public Transaction Transaction { get; set; }
    public override String ToString()
    {
        return GeneralData.ToString() + InitialState.ToString() + Transaction.ToString();
    }
}
public class GeneralData
{
    public string FaultName { get; set; }
    public int SwcId { get; set; }
    public string Severity { get; set; }
    public string Contract { get; set; }
    public string FunctionName { get; set; }
    public int PcAddress { get; set; }

    //TODO legyen-e int tömb
    public string EstimatedGasUsage { get; set; }
    public string Description { get; set; }
    public string File { get; set; }

    //maybe redundant
    public string Code { get; set; }
    public override String ToString()
    {
        return $"Fault Name: {FaultName}\n" +
            $"SWC ID: {SwcId}\n" +
            $"Severity: {Severity}\n" +
            $"Contract: {Contract}\n" +
            $"Function Name: {FunctionName}\n" +
            $"PC Address: {PcAddress}\n" +
            $"Estimated Gas Usage: {EstimatedGasUsage}\n" +
            $"Description: {Description}\n" +
            $"File: {File}\n" +
            $"Code: {Code}\n";
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
        return Creator.ToString() + "\n" + Attacker.ToString();
    }
}

public class Account
{
    public string Name { get; set; }
    public string Balance { get; set; }
    public int Nonce { get; set; }
    public string Storage { get; set; }
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
    public string Caller { get; set; }
    public string Function { get; set; }
    public string DecodedData { get; set; }
    public string Value { get; set; }
    public override String ToString()
    {
        return $"Caller: {Caller}\n" +
               $"Function: {Function}\n" +
               $"DecodedData: {DecodedData}\n" +
               $"Value: {Value}\n";
    }
}
