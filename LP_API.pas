unit LP_API;

interface

uses
  System.SysUtils, System.Classes, System.NetEncoding,
  System.JSON, System.DateUtils, System.Hash,
  IdHTTP, IdSSLOpenSSL,IdSSLOpenSSLHeaders,
  LP_Models, LP_Crypto;

const
  LP_BASE_URL    = 'https://appgateway.leapmotor-international.de';
  LP_APP_VERSION = '1.12.3';
  LP_SOURCE      = 'leapmotor';
  LP_CHANNEL     = '1';
  LP_DEVICE_TYPE = '1';
  LP_P12_ENC_ALG = '1';
  LP_LANGUAGE    = 'it-IT';

type
  TLPClient = class
  private
    FHTTP       : TIdHTTP;
    FSSLHandler : TIdSSLIOHandlerSocketOpenSSL;
    FSession    : TLPSession;
    FAppCertFile: string;
    FAppKeyFile : string;
    FSignKey    : TBytes;
    FLastLoginResponse: string;
    function  GenerateNonce: string;
    function  GenerateTimestamp: string;
    function  BuildSignKey: TBytes;

    function  BuildLoginSign(const ADeviceId, AUsername, APassword,
                              ANonce, ATimestamp: string): string;
    function  BuildHMACSign(const AFields: array of string): string;

    procedure SetCommonHeaders(const ANonce, ATimestamp, ASign: string);
    procedure SetAuthHeaders;
    procedure SetAppCert;
    procedure SetAccountCert;

    function  PostRequest(const APath, ABody: string): TLPApiResponse;

    function  ParseLoginResponse(const AJSON: string): Boolean;
    function  ParseVehicleList(const AJSON: string): TLPVehicleList;
    function  ParseVehicleStatus(const AJSON: string): TLPVehicleStatus;
    function HandleVerifyPeer(Certificate: TIdX509; AOk: Boolean;ADepth, AError: Integer): Boolean;

  public
    constructor Create(const AAppCertFile, AAppKeyFile: string);
    destructor  Destroy; override;

    function Login(const AUsername, APassword: string): Boolean;
    function GetVehicleList: TLPVehicleList;
    function GetVehicleStatus(const AVIN, ACarType: string): TLPVehicleStatus;

    property Session: TLPSession read FSession;
    property LastLoginResponse: string read FLastLoginResponse;
  end;

implementation

{ TLPClient }

constructor TLPClient.Create(const AAppCertFile, AAppKeyFile: string);
begin
  inherited Create;

  //IdOpenSSLSetLibPath(ExtractFilePath(ParamStr(0)));

 FSSLHandler := TIdSSLIOHandlerSocketOpenSSL.Create(nil);
FSSLHandler.SSLOptions.Method := sslvSSLv23;
FSSLHandler.SSLOptions.Mode := sslmClient;
FSSLHandler.SSLOptions.VerifyMode := [];
FSSLHandler.SSLOptions.VerifyDepth := 0;
FSSLHandler.SSLOptions.CipherList := '';
FSSLHandler.OnVerifyPeer := HandleVerifyPeer;

  FHTTP := TIdHTTP.Create(nil);
  FHTTP.IOHandler       := FSSLHandler;
  FHTTP.HandleRedirects := True;
  FHTTP.ConnectTimeout  := 30000;
  FHTTP.ReadTimeout     := 30000;
  FHTTP.Request.ContentType := 'application/x-www-form-urlencoded; charset=UTF-8';

  FAppCertFile := AAppCertFile;
  FAppKeyFile  := AAppKeyFile;
  FSession.Clear;
  FSession.DeviceId := Copy(
    THashSHA2.GetHashString(
      FormatDateTime('yyyymmddhhnnsszzz', Now) + IntToStr(Random(999999)),
      SHA256),
    1, 32);
end;

destructor TLPClient.Destroy;
begin
  FHTTP.Free;
  FSSLHandler.Free;
  inherited;
end;

function TLPClient.GenerateNonce: string;
begin
  Result := IntToStr(100000 + Random(9900000));
end;

function TLPClient.GenerateTimestamp: string;
begin
  Result := IntToStr(DateTimeToUnix(Now, False) * 1000);
end;

function TLPClient.BuildSignKey: TBytes;
begin
  if not FSession.IsAuthenticated then
    raise Exception.Create('Not authenticated');
  Result := HKDF_SHA256(FSession.SignIkm, FSession.SignSalt, FSession.SignInfo);
end;

function TLPClient.BuildLoginSign(const ADeviceId, AUsername, APassword,
                                   ANonce, ATimestamp: string): string;
var
  SignInput: string;
begin
  SignInput :=
    LP_LANGUAGE    +
    LP_DEVICE_TYPE +
    ADeviceId      +
    '1'            +
    AUsername      +
    '0'            +
    '1'            +
    ANonce         +
    APassword      +
    '20260204'     +
    LP_SOURCE      +
    ATimestamp     +
    LP_APP_VERSION;
  Result := SHA256Hex(SignInput);
end;

function TLPClient.BuildHMACSign(const AFields: array of string): string;
var
  SignInput: string;
  S: string;
  Key: TBytes;
begin
  SignInput := '';
  for S in AFields do
    SignInput := SignInput + S;
  Key := BuildSignKey;
  Result := HMACSHA256Hex(Key, SignInput);
end;

procedure TLPClient.SetCommonHeaders(const ANonce, ATimestamp, ASign: string);
begin
  FHTTP.Request.RawHeaders.Values['acceptLanguage'] := LP_LANGUAGE;
  FHTTP.Request.RawHeaders.Values['channel']        := LP_CHANNEL;
  FHTTP.Request.RawHeaders.Values['deviceType']     := LP_DEVICE_TYPE;
  FHTTP.Request.RawHeaders.Values['X-P12_ENC_ALG']  := LP_P12_ENC_ALG;
  FHTTP.Request.RawHeaders.Values['source']         := LP_SOURCE;
  FHTTP.Request.RawHeaders.Values['version']        := LP_APP_VERSION;
  FHTTP.Request.RawHeaders.Values['nonce']          := ANonce;
  FHTTP.Request.RawHeaders.Values['deviceId']       := FSession.DeviceId;
  FHTTP.Request.RawHeaders.Values['timestamp']      := ATimestamp;
  FHTTP.Request.RawHeaders.Values['sign']           := ASign;
end;

procedure TLPClient.SetAuthHeaders;
begin
  FHTTP.Request.RawHeaders.Values['userId'] := FSession.UserId;
  FHTTP.Request.RawHeaders.Values['token']  := FSession.Token;
end;

procedure TLPClient.SetAppCert;
begin
  FSSLHandler.SSLOptions.CertFile := FAppCertFile;
  FSSLHandler.SSLOptions.KeyFile  := FAppKeyFile;
end;

procedure TLPClient.SetAccountCert;
begin
  FSSLHandler.SSLOptions.CertFile := FSession.AccountCertFile;
  FSSLHandler.SSLOptions.KeyFile  := FSession.AccountKeyFile;
end;

function TLPClient.PostRequest(const APath, ABody: string): TLPApiResponse;
var
  URL       : string;
  PostStream: TStringStream;
  RespStr   : string;
  J         : TJSONValue;
begin
  Result.Clear;
  URL        := LP_BASE_URL + APath;
  PostStream := TStringStream.Create(ABody, TEncoding.UTF8);
  try
    try
      RespStr        := FHTTP.Post(URL, PostStream);
      Result.RawJSON := RespStr;
      J := TJSONObject.ParseJSONValue(RespStr);
      if Assigned(J) then
      try
        Result.Code    := J.GetValue<Integer>('code', -1);
        Result.Message := J.GetValue<string>('message', '');
        Result.Success := (Result.Code = 0);
      finally
        J.Free;
      end;
    except
    on E: EIdHTTPProtocolException do
    begin
      Result.Success := False;
      Result.Message := E.Message;
      Result.RawJSON := E.ErrorMessage;
    end;
    on E: Exception do
    begin
      Result.Success := False;
      Result.Message := E.Message;
      Result.RawJSON := 'EXCEPTION: ' + E.ClassName + ' - ' + E.Message;
    end;
end;
  finally
    PostStream.Free;
  end;
end;

function TLPClient.Login(const AUsername, APassword: string): Boolean;
var
  Nonce, Timestamp, Sign, Body: string;
  Resp: TLPApiResponse;
begin
  Result := False;
  Nonce     := GenerateNonce;
  Timestamp := GenerateTimestamp;
  Sign      := BuildLoginSign(FSession.DeviceId, AUsername, APassword,
                               Nonce, Timestamp);

  // Certificato PRIMA di tutto
  FSSLHandler.SSLOptions.CertFile := FAppCertFile;
  FSSLHandler.SSLOptions.KeyFile  := FAppKeyFile;

  SetCommonHeaders(Nonce, Timestamp, Sign);

  Body :=
    'isRecoverAcct=0' +
    '&password='  + TNetEncoding.URL.Encode(APassword) +
    '&policyId=20260204' +
    '&loginMethod=1' +
    '&email=' + TNetEncoding.URL.Encode(AUsername);

  Resp := PostRequest('/carownerservice/oversea/acct/v1/login', Body);
  FLastLoginResponse := Resp.RawJSON + ' | MSG: ' + Resp.Message;

  if not Resp.Success then
    Exit;

  Result := ParseLoginResponse(Resp.RawJSON);
  if Result then
    FSignKey := BuildSignKey;
end;

function TLPClient.ParseLoginResponse(const AJSON: string): Boolean;
var
  J   : TJSONObject;
  Data: TJSONObject;
begin
  Result := False;
  J := TJSONObject.ParseJSONValue(AJSON) as TJSONObject;
  if not Assigned(J) then Exit;
  try
    if J.GetValue<Integer>('code', -1) <> 0 then Exit;
    Data := J.GetValue<TJSONObject>('data');
    if not Assigned(Data) then Exit;

    FSession.UserId       := Data.GetValue<string>('id', '');
    FSession.Token        := Data.GetValue<string>('token', '');
    FSession.SignIkm      := Data.GetValue<string>('signIkm', '');
    FSession.SignSalt     := Data.GetValue<string>('signSalt', '');
    FSession.SignInfo     := Data.GetValue<string>('signInfo', '');
    FSession.RefreshToken := Data.GetValue<string>('refreshToken', '');
    FSession.Base64Cert   := Data.GetValue<string>('base64Cert', '');

    Result := FSession.IsAuthenticated;
  finally
    J.Free;
  end;
end;

function TLPClient.GetVehicleList: TLPVehicleList;
var
  Nonce, Timestamp, Sign: string;
  Resp: TLPApiResponse;
begin
  SetLength(Result, 0);
  if not FSession.IsAuthenticated then Exit;

  Nonce     := GenerateNonce;
  Timestamp := GenerateTimestamp;

  // Campi ordinati alfabeticamente per chiave
  Sign := BuildHMACSign([
    LP_LANGUAGE,       // acceptLanguage
    LP_CHANNEL,        // channel
    FSession.DeviceId, // deviceId
    LP_DEVICE_TYPE,    // deviceType
    Nonce,             // nonce
    LP_SOURCE,         // source
    Timestamp,         // timestamp
    LP_APP_VERSION     // version
  ]);

  SetAccountCert;
  SetCommonHeaders(Nonce, Timestamp, Sign);
  SetAuthHeaders;

  Resp := PostRequest('/carownerservice/oversea/vehicle/v1/list', '');
  if Resp.Success then
    Result := ParseVehicleList(Resp.RawJSON);
end;

function TLPClient.ParseVehicleList(const AJSON: string): TLPVehicleList;
var
  J   : TJSONObject;
  Data: TJSONObject;
  Arr : TJSONArray;
  Item: TJSONObject;
  V   : TLPVehicle;
  I   : Integer;
begin
  SetLength(Result, 0);
  J := TJSONObject.ParseJSONValue(AJSON) as TJSONObject;
  if not Assigned(J) then Exit;
  try
    Data := J.GetValue<TJSONObject>('data');
    if not Assigned(Data) then Exit;

    Arr := Data.GetValue<TJSONArray>('bindcars');
    if Assigned(Arr) then
      for I := 0 to Arr.Count - 1 do
      begin
        Item := Arr.Items[I] as TJSONObject;
        V.Clear;
        V.VIN             := Item.GetValue<string>('vin', '');
        V.CarId           := Item.GetValue<string>('carId', '');
        V.CarType         := Item.GetValue<string>('carType', '');
        V.VehicleNickname := Item.GetValue<string>('vehicleNickname', '');
        V.UserNickname    := Item.GetValue<string>('userNickname', '');
        V.IsShared        := False;
        Result := Result + [V];
      end;

    // Veicoli condivisi
    Arr := Data.GetValue<TJSONArray>('sharedcars');
    if Assigned(Arr) then
      for I := 0 to Arr.Count - 1 do
      begin
        Item := Arr.Items[I] as TJSONObject;
        V.Clear;
        V.VIN             := Item.GetValue<string>('vin', '');
        V.CarId           := Item.GetValue<string>('carId', '');
        V.CarType         := Item.GetValue<string>('carType', '');
        V.VehicleNickname := Item.GetValue<string>('vehicleNickname', '');
        V.UserNickname    := Item.GetValue<string>('userNickname', '');
        V.IsShared        := True;
        Result := Result + [V];
      end;
  finally
    J.Free;
  end;
end;

function TLPClient.GetVehicleStatus(const AVIN, ACarType: string): TLPVehicleStatus;
var
  Nonce, Timestamp, Sign, Body, CarTypePath: string;
  Resp: TLPApiResponse;
begin
  Result.Clear;
  if not FSession.IsAuthenticated then Exit;

  Nonce       := GenerateNonce;
  Timestamp   := GenerateTimestamp;
  CarTypePath := LowerCase(ACarType);

  // Campi ordinati alfabeticamente — include vin
  Sign := BuildHMACSign([
    LP_LANGUAGE,       // acceptLanguage
    LP_CHANNEL,        // channel
    FSession.DeviceId, // deviceId
    LP_DEVICE_TYPE,    // deviceType
    Nonce,             // nonce
    LP_SOURCE,         // source
    Timestamp,         // timestamp
    LP_APP_VERSION,    // version
    AVIN               // vin
  ]);

  SetAccountCert;
  SetCommonHeaders(Nonce, Timestamp, Sign);
  SetAuthHeaders;

  Body := 'vin=' + TNetEncoding.URL.Encode(AVIN);
  Resp := PostRequest(
    '/carownerservice/oversea/vehicle/v1/status/get/' + CarTypePath, Body);

  if Resp.Success then
    Result := ParseVehicleStatus(Resp.RawJSON);
end;

function TLPClient.ParseVehicleStatus(const AJSON: string): TLPVehicleStatus;
var
  J, Data: TJSONObject;
begin
  Result.Clear;
  J := TJSONObject.ParseJSONValue(AJSON) as TJSONObject;
  if not Assigned(J) then Exit;
  try
    Data := J.GetValue<TJSONObject>('data');
    if not Assigned(Data) then Exit;

    // Batteria
    Result.Battery.SOC              := Data.GetValue<Integer>('soc', 0);
    Result.Battery.ExpectedMileage  := Data.GetValue<Integer>('expectedMileage', 0);
    Result.Battery.BatteryVoltage   := Data.GetValue<Double>('batteryVoltage', 0);
    Result.Battery.BatteryCurrent   := Data.GetValue<Double>('batteryCurrent', 0);
    Result.Battery.ChargeRemainTime := Data.GetValue<Integer>('chargeRemainTime', 0);
    Result.Battery.ChargeSocSetting := Data.GetValue<Integer>('chargesocSetting', 80);
    Result.Battery.DumpEnergyKWh    := Data.GetValue<Integer>('dumpEnergy', 0) / 1000.0;
    Result.Battery.IsCharging       := Data.GetValue<Integer>('chargeState', 0) > 0;

    // Guida
    Result.Driving.TotalMileage := Data.GetValue<Integer>('totalMileage', 0);
    Result.Driving.Speed        := Data.GetValue<Integer>('speed', 0);
    Result.Driving.GearStatus   := Data.GetValue<Integer>('gearStatus', 0);
    Result.Driving.IsParked     := Data.GetValue<Integer>('gearStatus', 0) = 0;

    // GPS
    Result.Location.Latitude   := Data.GetValue<Double>('latitude', 0);
    Result.Location.Longitude  := Data.GetValue<Double>('longitude', 0);
    Result.Location.PrivacyGPS := Data.GetValue<Integer>('privacyGPS', 0);

    // Clima
    Result.Climate.ACSwitch    := Data.GetValue<Boolean>('acSwitch', False);
    Result.Climate.ACSetting   := Data.GetValue<Double>('acSetting', 0);
    Result.Climate.ACVolume    := Data.GetValue<Integer>('acAirVolume', 0);
    Result.Climate.OutdoorTemp := Data.GetValue<Integer>('outdoorTemp', 0);
    Result.Climate.PTCState    := Data.GetValue<Integer>('ptcState', 0);

    // Porte
    Result.Doors.IsLocked  := Data.GetValue<Boolean>('driverDoorLockStatus', False);
    Result.Doors.TrunkOpen := Data.GetValue<Boolean>('bbcmBackDoorStatus', False);

    // Finestre
    Result.Windows.LeftFrontPercent  := Data.GetValue<Integer>('leftFrontWindowPercent', 0);
    Result.Windows.RightFrontPercent := Data.GetValue<Integer>('rightFrontWindowPercent', 0);
    Result.Windows.LeftRearPercent   := Data.GetValue<Integer>('leftRearWindowPercent', 0);
    Result.Windows.RightRearPercent  := Data.GetValue<Integer>('rightRearWindowPercent', 0);
    Result.Windows.SunShade          := Data.GetValue<Integer>('sunShade', 0);

    // Gomme (kPa)
    Result.Tires.FrontLeftKPa  := Data.GetValue<Integer>('leftFrontTirePressure', 0);
    Result.Tires.FrontRightKPa := Data.GetValue<Integer>('rightFrontTirePressure', 0);
    Result.Tires.RearLeftKPa   := Data.GetValue<Integer>('leftRearTirePressure', 0);
    Result.Tires.RearRightKPa  := Data.GetValue<Integer>('rightRearTirePressure', 0);

    // Connettività
    Result.Connectivity.BluetoothState := Data.GetValue<Boolean>('bluetoothState', False);
    Result.Connectivity.HotspotState   := Data.GetValue<Boolean>('hotspotState', False);
    Result.Connectivity.BluetoothAddr  := Data.GetValue<string>('bluetoothAddr', '');
  finally
    J.Free;
  end;
end;

function TLPClient.HandleVerifyPeer(Certificate: TIdX509; AOk: Boolean;
  ADepth, AError: Integer): Boolean;
begin
  Result := True; // accetta qualsiasi certificato server
end;

end.
