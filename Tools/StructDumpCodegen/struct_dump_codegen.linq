<Query Kind="Program">
  <Reference>&lt;RuntimeDirectory&gt;\System.Drawing.dll</Reference>
  <Reference>&lt;RuntimeDirectory&gt;\System.IO.dll</Reference>
  <Reference>&lt;RuntimeDirectory&gt;\System.Net.dll</Reference>
  <Reference>&lt;RuntimeDirectory&gt;\System.Numerics.dll</Reference>
  <Reference>&lt;RuntimeDirectory&gt;\System.Numerics.Vectors.dll</Reference>
  <Reference>&lt;RuntimeDirectory&gt;\System.Security.dll</Reference>
  <Namespace>System.Collections</Namespace>
  <Namespace>System.Collections.Concurrent</Namespace>
  <Namespace>System.Collections.Generic</Namespace>
  <Namespace>System.Collections.Specialized</Namespace>
  <Namespace>System.Drawing</Namespace>
  <Namespace>System.Drawing.Imaging</Namespace>
  <Namespace>System.IO</Namespace>
  <Namespace>System.IO.MemoryMappedFiles</Namespace>
  <Namespace>System.IO.Pipes</Namespace>
  <Namespace>System.IO.Ports</Namespace>
  <Namespace>System.Net</Namespace>
  <Namespace>System.Net.Sockets</Namespace>
  <Namespace>System.Numerics</Namespace>
  <Namespace>System.Runtime.InteropServices</Namespace>
  <Namespace>System.Runtime.InteropServices</Namespace>
  <Namespace>System.Runtime.Serialization</Namespace>
  <Namespace>System.Runtime.Serialization.Formatters.Binary</Namespace>
  <Namespace>System.Security</Namespace>
  <Namespace>System.Security.AccessControl</Namespace>
  <Namespace>System.Security.Cryptography</Namespace>
  <Namespace>System.Security.Principal</Namespace>
  <Namespace>System.Text</Namespace>
  <Namespace>System.Threading</Namespace>
  <Namespace>System.Threading.Tasks</Namespace>
</Query>

/*
Script to turn a struct definition into C++ code that prints out its contents. So far it supports USHORT, ULONG, and UCHAR.

This was written specifically for IDENTIFY_DEVICE_DATA in order to speed up writing ATAIdentifyDump.

This can probably be used for similar structs too, so it might be useful elsewhere.
*/

const string SourceFile = @"C:\Users\Graham\Source\Repos\al-khaser\Tools\ATAIdentifyDump\IdentifyDeviceData.h";
const string StructVar = "idd";
const bool SwapStringEndian = true; // for IDENTIFY_DEVICE_DATA

void Main()
{
	
	string[] lines = File.ReadAllLines(SourceFile);
	
	bool foundStart = false;
	bool inStruct = false;
	var structLines = new List<string>();
	
	var output = new StringBuilder();
	
	foreach (string rawLine in lines)
	{
		var line = rawLine.Trim().TrimEnd(';');
		if (!foundStart)
		{
			if (line.StartsWith("typedef struct"))
			{
				foundStart = true;
			}
			continue;
		}
		
		if (line.StartsWith("struct {"))
		{
			if (inStruct)
			{
				throw new InvalidDataException();
			}
			
			// we're starting a nested structure
			inStruct = true;
			structLines.Clear();
			continue;
		}
		
		if (line.StartsWith("}"))
		{
			if (!inStruct)
			{
				Console.WriteLine("// end");
				break;
			}
			
			// we're ending a nested structure
			var structNameMatch = Regex.Match(line, "^}\\s+([a-zA-Z0-9]+)$");
			if (!structNameMatch.Success)
			{
				throw new InvalidDataException();
			}
			
			string structName = structNameMatch.Groups[1].Value;
			
			inStruct = false;
			foreach (string structLine in structLines)
			{
				ProcessLine(StructVar, structLine, structName);
			}
			continue;
		}
		
		if (inStruct)
		{
			structLines.Add(line);
			continue;
		}
		
		ProcessLine(StructVar, line);
	}
}

void ProcessLine(string structvar, string line, string structname = null)
{
	string[] parts = line.Split(" ".ToCharArray(), StringSplitOptions.RemoveEmptyEntries);
	
	string fieldType = null;
	string fieldName = null;
	int arraySize = 0;
	
	if (parts.Length == 2)
	{
		fieldType = parts[0];
		if (parts[1].Contains("["))
		{
			var arrayMatch = Regex.Match(parts[1], "^([a-zA-Z0-9]+)\\[(\\d+)\\]$");
			if (!arrayMatch.Success)
			{
				throw new InvalidDataException();
			}
			fieldName = arrayMatch.Groups[1].Value;
			arraySize = int.Parse(arrayMatch.Groups[2].Value);
		}
		else
		{
			fieldName = parts[1];
		}
	}
	else
	{
		if (!parts.Contains(":"))
		{
			throw new InvalidDataException();
		}

		fieldType = parts[0];
		fieldName = parts[1];
	}
	
	if (structname != null)
	{
		structname += ".";
	}
	
	if (fieldType == "USHORT")
	{
		if (arraySize == 0)
		{
			Console.WriteLine($"printf(\"{structname ?? ""}{fieldName} = %hu\\r\\n\", {structvar}->{structname ?? ""}{fieldName});");
		}
		else
		{
			for (int i = 0; i < arraySize; i++)
			{
				Console.WriteLine($"printf(\"{structname ?? ""}{fieldName}[{i}] = %hu\\r\\n\", {structvar}->{structname ?? ""}{fieldName}[{i}]);");
			}
		}
	}
	else if (fieldType == "ULONG")
	{
		if (arraySize == 0)
		{
			Console.WriteLine($"printf(\"{structname ?? ""}{fieldName} = %lu\\r\\n\", {structvar}->{structname ?? ""}{fieldName});");
		}
		else
		{
			for (int i = 0; i < arraySize; i++)
			{
				Console.WriteLine($"printf(\"{structname ?? ""}{fieldName}[{i}] = %lu\\r\\n\", {structvar}->{structname ?? ""}{fieldName}[{i}]);");
			}
		}
	}
	else if (fieldType == "UCHAR")
	{
		if (arraySize == 0)
		{
			Console.WriteLine($"printf(\"{structname ?? ""}{fieldName} = %d\\r\\n\", {structvar}->{structname ?? ""}{fieldName});");
		}
		else
		{
			string format = string.Concat(Enumerable.Repeat("%c", arraySize));
			Console.Write($"printf(\"{structname ?? ""}{fieldName} = \\\"{format}\\\"\\r\\n\"");
			for (int i = 0; i < arraySize; i++)
			{
				int ni = i;
				if (SwapStringEndian)
				{
					ni = (i - (i % 2)) + (1 - (i % 2));
				}
				Console.Write($", {structvar}->{structname ?? ""}{fieldName}[{ni}]");
			}
			Console.WriteLine(");");
		}
	}
	else
	{
		throw new InvalidDataException();
	}
}