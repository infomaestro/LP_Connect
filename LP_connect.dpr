program LP_connect;
uses
  System.StartUpCopy,
  FMX.Forms,
  LP_CoreBase in 'LP_CoreBase.pas',
  {$IFDEF MSWINDOWS}
  LP_CoreWindows in 'LP_CoreWindows.pas',
  {$ENDIF }
  {$IFDEF ANDROID}
  LP_CoreAndroid in 'LP_CoreAndroid.pas',
  PowerManager in 'PowerManager.pas',
  {$ENDIF }
  main in 'main.pas' {FormMain},
  Utility in 'Utility.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TFormMain, FormMain);
  Application.Run;
end.
