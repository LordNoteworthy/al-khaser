Sub Document_Close()

   On Error Resume Next

   ActiveDocument.Range.Text = "Al-khaser 0.69 by Lord Noteworthy" & vbCrLf & vbCrLf & "Public malware techniques used in the wild: Virtual Machine, Emulation, Debuggers, Sandbox detection." & vbCrLf
   
   checkFileMRU
End Sub


Public Sub checkFileMRU()

    printMsg "[*] Checking Application.RecentFiles.Count ..."

    ActiveDocument.Range.Text = ActiveDocument.Range.Text & msg
    If Application.RecentFiles.Count < 3 Then
        printMsg "BAD"
    Else
        printMsg "GOOD"
    End If
    
End Sub


Public Function printMsg(msg)

   ActiveDocument.Range.Text = ActiveDocument.Range.Text & msg
    
End Function