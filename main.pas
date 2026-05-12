unit Main;

interface

uses
  {$IFDEF MSWINDOWS}
  LP_CoreWindows,
  {$ENDIF}
  {$IFDEF ANDROID}
  LP_CoreAndroid,
  PowerManager,
  FMX.Platform, Androidapi.JNI.GraphicsContentViewText,
  Androidapi.Helpers, Androidapi.JNI.JavaTypes,
  Androidapi.JNI.App,Androidapi.JNIBridge,System.Messaging,FMX.Platform.Android,
  {$ENDIF}
   System.Classes, FMX.Types, FMX.Controls, FMX.Controls.Presentation,
  FMX.StdCtrls,FMX.Forms, FMX.Memo.Types, FMX.ScrollBox, FMX.Memo,
  System.JSON, System.SysUtils,System.IOUtils,System.Generics.Collections,
  System.Threading,System.Types,
  FMX.Dialogs, FMX.Edit, FMX.Layouts;



type
  TFormMain = class(TForm)
    Memo1: TMemo;
    PanelLogin: TPanel;
    Label1: TLabel;
    ButtonLoadCrt: TButton;
    Label2: TLabel;
    ButtonLoadKey: TButton;
    EditAppCrt: TEdit;
    EditAppKey: TEdit;
    Layout1: TLayout;
    ButtonLogin: TButton;
    ButtonRefresh: TButton;
    Switch1: TSwitch;
    Layout2: TLayout;
    Label5: TLabel;
    TimerAuto: TTimer;
    Layout3: TLayout;
    LabelKph: TLabel;
    LabelConsumo: TLabel;
    LabelCV: TLabel;
    StyleBook1: TStyleBook;
    EditPassword: TEdit;
    Label4: TLabel;
    EditEmail: TEdit;
    Label3: TLabel;
    LabelMaxSpeed: TLabel;
    LabelMaxConsumo: TLabel;
    LabelMaxPower: TLabel;
    LabelMaxRigen: TLabel;
    LabelRange: TLabel;
    LabelBatteryHealth: TLabel;
    procedure ButtonLoginClick(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure ButtonRefreshClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure ButtonLoadCrtClick(Sender: TObject);
    procedure ButtonLoadKeyClick(Sender: TObject);
    procedure Switch1Switch(Sender: TObject);
    procedure TimerAutoTimer(Sender: TObject);


  private
    const
    CAP_NETTA_NOMINALE_KWH = 39.5;   // ← cap netta T03 nuovo (calibra dopo test al 100%)
    SOC_AFFIDABILE_MIN     = 30;
    SOC_AFFIDABILE_MAX     = 70;
    TEMP_AFFIDABILE_MIN    = 15;
    TEMP_AFFIDABILE_MAX    = 30;
    var
    LC      : TLPConnect;
    FVIN    : String;
    FLogged : boolean;
    fSpeed    : Double;
    fVoltage  : Double;
    fCurrent  : Double;
    fPowerKW  : Double;
    fConsumo  : Double;
    fMaxSpeed : Double;
    fMaxPower : DOuble;
    fMaxConsumo : Double;
    fMaxRigen : Double;
    procedure Log(const AMsg: string);
    procedure ResetStats;
    {$IFDEF ANDROID}
    procedure OnActivityResult(requestCode, resultCode: Integer;data: JIntent);
    {$ENDIF}
  public
    { Public declarations }
  end;

var
  FormMain: TFormMain;

implementation

{$R *.fmx}
uses LP_CoreBase,utility;



procedure TFormMain.ButtonLoadCrtClick(Sender: TObject);
begin
{$IFDEF MSWINDOWS}
  var OD := TOpenDialog.Create(nil);
  try
    OD.Title  := 'Seleziona certificato app.crt';
    OD.Filter := 'Certificate files (*.crt)|*.crt|All files (*.*)|*.*';
    OD.DefaultExt := 'crt';
    if OD.Execute then
    begin
      var Dest := ExtractFilePath(ParamStr(0)) + 'app.crt';
      TFile.Copy(OD.FileName, Dest, True);
      EditAppCrt.Text := Dest;
      Log('Caricato: ' + Dest);
    end;
  finally
    OD.Free;
  end;
{$ENDIF}
{$IFDEF ANDROID}
  var Intent := TJIntent.JavaClass.init(
    TJIntent.JavaClass.ACTION_GET_CONTENT);
  Intent.setType(StringToJString('*/*'));
  Intent.addCategory(TJIntent.JavaClass.CATEGORY_OPENABLE);
  TAndroidHelper.Activity.startActivityForResult(Intent, 101);
{$ENDIF}
end;

procedure TFormMain.ButtonLoadKeyClick(Sender: TObject);
begin
{$IFDEF MSWINDOWS}
  var OD := TOpenDialog.Create(nil);
  try
    OD.Title  := 'Seleziona chiave app.key';
    OD.Filter := 'Key files (*.key)|*.key|All files (*.*)|*.*';
    OD.DefaultExt := 'key';
    if OD.Execute then
    begin
      var Dest := ExtractFilePath(ParamStr(0)) + 'app.key';
      TFile.Copy(OD.FileName, Dest, True);
      EditAppKey.Text := Dest;
      Log('Caricato: ' + Dest);
    end;
  finally
    OD.Free;
  end;
{$ENDIF}
{$IFDEF ANDROID}
  var Intent := TJIntent.JavaClass.init(
    TJIntent.JavaClass.ACTION_GET_CONTENT);
  Intent.setType(StringToJString('*/*'));
  Intent.addCategory(TJIntent.JavaClass.CATEGORY_OPENABLE);
  TAndroidHelper.Activity.startActivityForResult(Intent, 102);
{$ENDIF}
end;

procedure TFormMain.ButtonLoginClick(Sender: TObject);
begin
  if FLogged then
  begin
    Log('Logout...');
    ButtonLogin.Text := 'Login';
    LC.Free;
    LC := nil;
    FLogged :=false;
    PanelLogin.Visible := true;
    exit;
  end;

  Log('Login...');
  TTask.Run(procedure
  begin
    try
      ButtonLogin.Enabled:=false;
      LC := TLPConnect.Create(EditAppCrt.Text, EditAppKey.Text);
      try
        LC.Login(Editemail.Text, EditPassword.Text);
        LC.SaveCredentials(Editemail.Text, EditPassword.Text,
          TPath.Combine(TPath.GetHomePath, 'lp_cred.dat'));
        TThread.Synchronize(nil, procedure
        begin
          Log('Login OK — UserID: ' + LC.UserID);
          FLogged := true;
        end);
      except on E: Exception do
        TThread.Synchronize(nil, procedure
        begin
          Log('ERRORE: ' + E.ClassName + ' — ' + E.Message);
          LC.Free;
          LC := nil;
        end);
      end;
    except on E: Exception do
      TThread.Synchronize(nil, procedure
      begin
        Log('ERRORE Create: ' + E.ClassName + ' — ' + E.Message);

      end);
    end;


    if FLogged then
    begin
      ButtonLogin.Text := 'Log ->out';
      PanelLogin.Visible := false;
    end
    else
    begin
      ButtonLogin.Enabled:=true;
      exit;
    end;

    // lettura VIN
    try
      var VL := LC.GetVehicleList;
      try
        var Data := VL.GetValue<TJSONObject>('data');
        var Cars := Data.GetValue<TJSONArray>('bindcars');
        if (Cars = nil) or (Cars.Count = 0) then
          Cars := Data.GetValue<TJSONArray>('sharedcars');
        if (Cars <> nil) and (Cars.Count > 0) then
        begin
          FVIN := (Cars.Items[0] as TJSONObject).GetValue<string>('vin');
          TThread.Synchronize(nil, procedure
          begin
            Log('VIN: ' + FVIN);
          end);
        end
        else
          TThread.Synchronize(nil, procedure
          begin
            Log('Nessun veicolo trovato');
          end);
      finally
        VL.Free;
        ButtonLogin.Enabled:=true;
      end;
    except on E: Exception do
      TThread.Synchronize(nil, procedure
      begin
        Log('ERRORE VIN: ' + E.Message);
      end);
    end;

  end);



end;

procedure TFormMain.ButtonRefreshClick(Sender: TObject);
begin
  if not Assigned(LC) then Exit;
  if FVIN = '' then
  begin
    Log('VIN non disponibile — eseguire prima il login');
    Exit;
  end;

  Log('GetVehicleStatus...');
  TTask.Run(procedure
begin
  try
    var Status := LC.GetVehicleStatus(FVIN, 't03');
    try
      var Data := Status.GetValue<TJSONObject>('data');
      var FS   := TFormatSettings.Invariant;

      // === Batteria / energia ===
      var Soc        := Data.GetValue<Double>('soc');
      var DumpEnergy := Data.GetValue<Double>('dumpEnergy');
      var CapacitaKwh: Double;
      if Soc > 0 then
        CapacitaKwh := (DumpEnergy / 1000.0) / (Soc / 100.0)
      else
        CapacitaKwh := 0;

      // === Posizione / movimento / odometro ===
      var sSoc     := Data.GetValue<string>('soc');
      var sRange   := Data.GetValue<string>('expectedMileage');
      var sRangeMi := Data.GetValue<string>('expectedMileageMile');
      var sOdo     := Data.GetValue<string>('totalMileage');
      var sLat     := Data.GetValue<string>('latitude');
      var sLon     := Data.GetValue<string>('longitude');
      var sLock    := BoolToStr(Data.GetValue<Boolean>('driverDoorLockStatus'), True);
      var sSpeed   := Data.GetValue<string>('speed');

      // === Derivati ===
      var RangeKm          := StrToFloatDef(sRange, 0, FS);
      var EfficienzaWhKm   := 0.0;
      var EfficienzaKwh100 := 0.0;
      var RangeFull        := 0.0;
      if RangeKm > 0 then
      begin
        EfficienzaWhKm   := DumpEnergy / RangeKm;
        EfficienzaKwh100 := (DumpEnergy / 1000.0) / RangeKm * 100.0;
      end;
      if Soc > 0 then
        RangeFull := RangeKm / (Soc / 100.0);

      // === Tensione / corrente / potenza ===
      var Voltage := StrToFloatDef(Data.GetValue<string>('batteryVoltage'), 0, FS);
      var Current := StrToFloatDef(Data.GetValue<string>('batteryCurrent'), 0, FS);
      var PowerKW := (Voltage * Current) / 1000.0;
      var sVoltage := Data.GetValue<string>('batteryVoltage');
      var sCurrent := Data.GetValue<string>('batteryCurrent');

      // === Clima ===
      var sAcSwitch    := BoolToStr(Data.GetValue<Boolean>('acSwitch'), True);
      var sAcSetting   := Data.GetValue<string>('acSetting');
      var sAcCoolHeat  := Data.GetValue<string>('acCoolingAndHeating');
      var sAcAirVol    := Data.GetValue<string>('acAirVolume');
      var sAcAirVolSet := Data.GetValue<string>('acAirVolumeSetting');
      var sAcWindDir   := Data.GetValue<string>('acWindDirection');
      var sAcCircle    := BoolToStr(Data.GetValue<Boolean>('acCircleMode'), True);
      var sAcTempMode  := BoolToStr(Data.GetValue<Boolean>('acTempMode'), True);
      var sPtcState    := Data.GetValue<string>('ptcState');
      var sPtcPowerSet := Data.GetValue<string>('ptcPowerSettingValue');
      var sOutdoorTemp := Data.GetValue<string>('outdoorTemp');
      var sMinCellTemp := Data.GetValue<string>('minSingleTemp');

      // === Carica ===
      var sChargeState   := Data.GetValue<string>('chargeState');
      var sSocTarget     := Data.GetValue<string>('chargesocSetting');
      var sChargeTime    := Data.GetValue<string>('chargeRemainTime');
      var sChargeTimeSet := Data.GetValue<string>('chargeTimeSetting');
      var sDcFastCharge  := Data.GetValue<string>('dcInputFastCharge');

      // === Pressioni gomme ===
      var sPressFL   := Data.GetValue<string>('leftFrontTirePressure');
      var sPressFR   := Data.GetValue<string>('rightFrontTirePressure');
      var sPressRL   := Data.GetValue<string>('leftRearTirePressure');
      var sPressRR   := Data.GetValue<string>('rightRearTirePressure');
      var sPressStFL := Data.GetValue<string>('leftFrontTirePressureState');
      var sPressStFR := Data.GetValue<string>('rightFrontTirePressureState');
      var sPressStRL := Data.GetValue<string>('leftRearTirePressureState');
      var sPressStRR := Data.GetValue<string>('rightRearTirePressureState');

      // === Porte e finestre ===
      var sDoorLbcm  := BoolToStr(Data.GetValue<Boolean>('lbcmDriverDoorStatus'), True);
      var sDoorRbcm  := BoolToStr(Data.GetValue<Boolean>('rbcmDriverDoorStatus'), True);
      var sDoorLR    := BoolToStr(Data.GetValue<Boolean>('lbcmLeftRearDoorStatus'), True);
      var sDoorRR    := BoolToStr(Data.GetValue<Boolean>('rbcmRightRearDoorStatus'), True);
      var sTrunk     := BoolToStr(Data.GetValue<Boolean>('bbcmBackDoorStatus'), True);
      var sWinRemote := Data.GetValue<string>('isSupportWindowsRemoteControl');
      var sWinFLp    := Data.GetValue<string>('leftFrontWindowPercent');
      var sWinFRp    := Data.GetValue<string>('rightFrontWindowPercent');
      var sWinRLp    := Data.GetValue<string>('leftRearWindowPercent');
      var sWinRRp    := Data.GetValue<string>('rightRearWindowPercent');
      var sWinFL     := BoolToStr(Data.GetValue<Boolean>('driverWindowStatus'), True);
      var sWinFR     := BoolToStr(Data.GetValue<Boolean>('rightFrontWindowStatus'), True);
      var sWinRL     := BoolToStr(Data.GetValue<Boolean>('leftRearWindowStatus'), True);
      var sWinRR     := BoolToStr(Data.GetValue<Boolean>('rightRearWindowStatus'), True);
      var sSunShade  := Data.GetValue<string>('sunShade');
      var sDoorAllow := BoolToStr(Data.GetValue<Boolean>('bcmDoorCtrlAllow'), True);

      // === Veicolo ===
      var sGear   := Data.GetValue<string>('gearStatus');
      var sKeyOn1 := BoolToStr(Data.GetValue<Boolean>('bcmKeyPositionOn1'), True);
      var sKeyOn3 := BoolToStr(Data.GetValue<Boolean>('bcmKeyPositionOn3'), True);

      // === Connettività ===
      var sBluetooth     := BoolToStr(Data.GetValue<Boolean>('bluetoothState'), True);
      var sBluetoothAddr := Data.GetValue<string>('bluetoothAddr');
      var sHotspot       := BoolToStr(Data.GetValue<Boolean>('hotspotState'), True);

      // === Tempi ===
      var sCollect   := Data.GetValue<string>('collectTime');
      var sCollectMs := Data.GetValue<string>('collectTimeMs');
      var sCreate    := Data.GetValue<string>('createTime');

      // === Privacy ===
      var sPrivacyGPS  := Data.GetValue<string>('privacyGPS');
      var sPrivacyData := Data.GetValue<string>('privacyData');



      var SoH := CalcolaSoH(
        CapacitaKwh,
        39.5,            // ← capacità nominale netta T03 (calibra dopo test 100%)
        Soc,
        StrToIntDef(sMinCellTemp,0),
        StrToIntDef(sChargeState,0),
        Current
      );

      TThread.Synchronize(nil, procedure
      var
        SavedScrollY: Single;
      begin
        SavedScrollY := Memo1.ViewportPosition.Y;
        Memo1.BeginUpdate;
        try
          Memo1.Text := '';
          //Log(Status.ToJSON);

          fSpeed   := CalibrateSpeed(StrToFloat(sSpeed, FS));
          fVoltage := Voltage;
          fCurrent := Current;
          fPowerKW := PowerKW;

          if fSpeed > 2.0 then
            fConsumo := (fPowerKW / fSpeed) * 100.0
          else
            fConsumo := 0;

          LabelKph.Text := FormatFloat('0', fSpeed) + ' km/h';
          if fConsumo <> 0 then
            LabelConsumo.Text := FormatFloat('0.0', fConsumo) + ' kWh/100km'
          else
            LabelConsumo.Text := 'ND kWh/100km';
          LabelCV.Text := FormatFloat('0', fPowerKW * 1.35962) + ' HP';


          // Max velocità reale
          if fSpeed > fMaxSpeed then
            fMaxSpeed := fSpeed;

          // Max potenza erogata (positiva = trazione)
          if fPowerKW > fMaxPower then
            fMaxPower := fPowerKW;

          // Max rigenerazione (potenza più negativa)
          if fPowerKW < fMaxRigen then
            fMaxRigen := fPowerKW;

          // Max consumo (solo quando in movimento e in trazione, non in rigenerazione)
          if (fSpeed > 2.0) and (fConsumo > 0) and (fConsumo > fMaxConsumo) then
            fMaxConsumo := fConsumo;

          // Aggiorna label
          LabelMaxSpeed.Text   := FormatFloat('0', fMaxSpeed) + '(max)';
          LabelMaxPower.Text   := FormatFloat('0', fMaxPower * 1.35962) +'(max)';
          LabelMaxRigen.Text   := FormatFloat('0.0', (fMaxRigen)) + '(rig)';
          LabelMaxConsumo.Text := FormatFloat('0.0', fMaxConsumo) + '(max)';
          LabelRange.Text := 'Range:'+FormatFloat('0', RangeKm) + '/' + FormatFloat('0', RangeFull) + ' km';

          if SoH.Reliable then
            LabelBatteryHealth.Text := FormatFloat('0.0', SoH.Value) + '% SoH stimato'
          else
            LabelBatteryHealth.Text := 'Non calcolabile: ' + SoH.Reason;



          Log('Velocità Tachimetro    : ' + sSpeed + ' km/h');
          Log('Velocità Reale (stima) : ' + FormatFloat('0', fSpeed) + ' km/h');
          Log('Batteria               : ' + sSoc + '%');
          Log('Range                  : ' + sRange + ' km (' + sRangeMi + ' mi)');
          Log('Range stimato a 100%   : ' + FormatFloat('0', RangeFull) + ' km');
          Log('Efficienza media BMS   : ' + FormatFloat('0.00', EfficienzaKwh100) + ' kWh/100km');
          Log('Odometro               : ' + sOdo + ' km');
          Log('Latitudine             : ' + sLat);
          Log('Longitudine            : ' + sLon);
          Log('Bloccata               : ' + sLock);
          Log('Capacità stimata       : ' + FormatFloat('0.0', CapacitaKwh) + ' kWh');
          Log('Energia residua        : ' + FormatFloat('0.0', DumpEnergy / 1000.0) + ' kWh');
          Log('Potenza istantanea     : ' + FormatFloat('0.0', PowerKW) + ' kW');

          Log('--- Clima ---');
          Log('AC acceso       : ' + sAcSwitch);
          Log('AC temp setting : ' + sAcSetting + ' °C');
          Log('AC riscald/raff : ' + sAcCoolHeat);
          Log('AC vol aria     : ' + sAcAirVol);
          Log('AC vol setting  : ' + sAcAirVolSet);
          Log('AC dir vento    : ' + sAcWindDir);
          Log('AC circ aria    : ' + sAcCircle);
          Log('AC modo temp    : ' + sAcTempMode);
          Log('PTC stato       : ' + sPtcState);
          Log('PTC power set   : ' + sPtcPowerSet);
          Log('Temp esterna    : ' + sOutdoorTemp + ' °C');
          Log('Temp min cella  : ' + sMinCellTemp + ' °C');

          Log('--- Batteria ---');
          Log('Stato carica    : ' + sChargeState);
          Log('SOC target      : ' + sSocTarget + '%');
          Log('Tempo ricarica  : ' + sChargeTime + ' min');
          Log('Ora prog.carica : ' + sChargeTimeSet);
          Log('DC fast charge  : ' + sDcFastCharge);
          Log('Tensione batt.  : ' + sVoltage + ' V');
          Log('Corrente batt.  : ' + sCurrent + ' A');

          Log('--- Pressioni gomme ---');
          Log('Ant.SX  : ' + sPressFL + ' kPa  stato: ' + sPressStFL);
          Log('Ant.DX  : ' + sPressFR + ' kPa  stato: ' + sPressStFR);
          Log('Post.SX : ' + sPressRL + ' kPa  stato: ' + sPressStRL);
          Log('Post.DX : ' + sPressRR + ' kPa  stato: ' + sPressStRR);

          Log('--- Porte e finestre ---');
          Log('Porta guida (lbcm): ' + sDoorLbcm);
          Log('Porta guida (rbcm): ' + sDoorRbcm);
          Log('Post.SX porta     : ' + sDoorLR);
          Log('Post.DX porta     : ' + sDoorRR);
          Log('Portellone        : ' + sTrunk);
          Log('Ctrl remoto fin.  : ' + sWinRemote);
          Log('Finestra ant.SX % : ' + sWinFLp);
          Log('Finestra ant.DX % : ' + sWinFRp);
          Log('Finestra post.SX %: ' + sWinRLp);
          Log('Finestra post.DX %: ' + sWinRRp);
          Log('Stato fin.ant.SX  : ' + sWinFL);
          Log('Stato fin.ant.DX  : ' + sWinFR);
          Log('Stato fin.post.SX : ' + sWinRL);
          Log('Stato fin.post.DX : ' + sWinRR);
          Log('Tettuccio         : ' + sSunShade);
          Log('Porta ctrl allow  : ' + sDoorAllow);

          Log('--- Veicolo ---');
          Log('Marcia            : ' + sGear);
          Log('Key pos ON1       : ' + sKeyOn1);
          Log('Key pos ON3       : ' + sKeyOn3);

          Log('--- Connettività ---');
          Log('Bluetooth         : ' + sBluetooth);
          Log('Bluetooth addr    : ' + sBluetoothAddr);
          Log('Hotspot           : ' + sHotspot);

          Log('--- Tempi ---');
          Log('Collect time      : ' + sCollect);
          Log('Collect time ms   : ' + sCollectMs);
          Log('Create time       : ' + sCreate);

          Log('--- Privacy ---');
          Log('Privacy GPS       : ' + sPrivacyGPS);
          Log('Privacy data      : ' + sPrivacyData);
        finally
          Memo1.EndUpdate;
        end;

        // 2. Ripristina scroll DOPO il refresh (in coda al message loop)
        TThread.ForceQueue(nil,
          procedure
          begin
            Memo1.ViewportPosition := TPointF.Create(0, SavedScrollY);
          end);
      end);
    finally
      Status.Free;
    end;
  except on E: Exception do
    TThread.Synchronize(nil, procedure
    begin
      Log('ERRORE: ' + E.Message);
    end);
  end;
end);

end;

procedure TFormMain.FormCreate(Sender: TObject);
begin
{$IFDEF MSWINDOWS}
  if fileexists(ExtractFilePath(ParamStr(0)) + 'app.crt') then
    EditAppCrt.Text :=  ExtractFilePath(ParamStr(0)) + 'app.crt'
  else
    EditAppCrt.Text := '<load app.crt>';

  if fileexists(ExtractFilePath(ParamStr(0)) + 'app.key') then
    EditAppKey.Text :=  ExtractFilePath(ParamStr(0)) + 'app.key'
  else
    EditAppKey.Text := '<load app.key>';

  ResetStats;
{$ENDIF}

{$IFDEF ANDROID}

  AcquireWakeLock; // EVITA LO SPEGNIMENTO SCHERMO


  if fileexists(TPath.Combine(TPath.GetDocumentsPath, 'app.crt')) then
    EditAppCrt.Text := TPath.Combine(TPath.GetDocumentsPath, 'app.crt')
  else
    EditAppCrt.Text := '<load app.crt>';

  if fileexists(TPath.Combine(TPath.GetDocumentsPath, 'app.key')) then
    EditAppKey.Text := TPath.Combine(TPath.GetDocumentsPath, 'app.key')
  else
  EditAppKey.Text := '<load app.key>';

  TMessageManager.DefaultManager.SubscribeToMessage(
    TMessageResultNotification,
    procedure(const Sender: TObject; const M: TMessage)
    begin
      var Msg := M as TMessageResultNotification;
      OnActivityResult(Msg.RequestCode, Msg.ResultCode, Msg.Value);
    end);


{$ENDIF}

  LPLogProc := procedure(const AMsg: string)
  begin
    Memo1.Lines.Add(AMsg);
  end;

try
  var e,p : string;

  LC.LoadCredentials(e,p,TPath.Combine(TPath.GetHomePath, 'lp_cred.dat'));
  EditEmail.Text := e;
  EditPassword.Text := p;
finally


end;
end;

procedure TFormMain.FormDestroy(Sender: TObject);
begin
{$IFDEF ANDROID}
ReleaseWakeLock;
{$ENDIF}
if Assigned(LC) then
  LC.Free;
end;



procedure TFormMain.Log(const AMsg: string);
begin
  //Memo1.Lines.Add(FormatDateTime('[hh:nn:ss] ', Now) + AMsg);
  Memo1.Lines.Add(AMsg);

end;

procedure TFormMain.Switch1Switch(Sender: TObject);
begin
  TimerAuto.Enabled := Switch1.IsChecked;
end;

procedure TFormMain.TimerAutoTimer(Sender: TObject);
begin
  ButtonRefreshClick(self);
end;

procedure TFormMain.ResetStats;
begin
  fMaxSpeed   := 0;
  fMaxPower   := 0;
  fMaxRigen   := 0;     // verrà aggiornato a valori negativi
  fMaxConsumo := 0;
end;
{$IFDEF ANDROID}
procedure TFormMain.OnActivityResult(requestCode, resultCode: Integer;
  data: JIntent);
var
  DestFile : string;
begin
  Log('OnActivityResult: ');
  if resultCode <> TJActivity.JavaClass.RESULT_OK then Exit;
  if data = nil then Exit;
  case requestCode of
    101: DestFile := TPath.Combine(TPath.GetDocumentsPath, 'app.crt');
    102: DestFile := TPath.Combine(TPath.GetDocumentsPath, 'app.key');
  else Exit;
  end;

  var Uri := data.getData;
  var IS_ := TAndroidHelper.Context.getContentResolver.openInputStream(Uri);
  var Buf := TJavaArray<Byte>.Create(8192);
  var BOS := TMemoryStream.Create;
  try
    var N := IS_.read(Buf, 0, 8192);
    while N > 0 do
    begin
      var Tmp: TBytes;
      SetLength(Tmp, N);
      for var I := 0 to N - 1 do Tmp[I] := Byte(Buf[I]);
      BOS.WriteBuffer(Tmp[0], N);
      N := IS_.read(Buf, 0, 8192);
    end;
    var OutBytes: TBytes;
    SetLength(OutBytes, BOS.Size);
    Move(BOS.Memory^, OutBytes[0], BOS.Size);
    TFile.WriteAllBytes(DestFile, OutBytes);
    Log('Caricato: ' + DestFile);

    // ✅ Fix: aggiorna il campo corretto
    case requestCode of
      101: EditAppCrt.Text := DestFile;
      102: EditAppKey.Text := DestFile;
    end;

  finally
    IS_.close;   // chiudi sempre lo stream Java
    Buf.Free;
    BOS.Free;
  end;
end;
{$ENDIF}

end.
