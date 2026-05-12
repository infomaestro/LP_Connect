unit LP_Models;

interface

uses
  System.SysUtils, System.Generics.Collections;

type
  // ---------------------------------------------------------------------------
  // Credenziali e sessione
  // ---------------------------------------------------------------------------
  TLPSession = record
    UserId     : string;
    Token      : string;
    SignIkm    : string;
    SignSalt   : string;
    SignInfo   : string;
    RefreshToken: string;
    Base64Cert : string;  // PKCS#12 base64 dal login
    DeviceId   : string;
    // Certificato account estratto dal P12 (path file temporanei)
    AccountCertFile: string;
    AccountKeyFile : string;
    procedure Clear;
    function IsAuthenticated: Boolean;
  end;

  // ---------------------------------------------------------------------------
  // Veicolo
  // ---------------------------------------------------------------------------
  TLPVehicle = record
    VIN            : string;
    CarId          : string;
    CarType        : string;  // es. "T03"
    VehicleNickname: string;
    UserNickname   : string;
    IsShared       : Boolean;
    Year           : string;
    procedure Clear;
  end;

  TLPVehicleList = TArray<TLPVehicle>;

  // ---------------------------------------------------------------------------
  // Stato batteria
  // ---------------------------------------------------------------------------
  TLPBattery = record
    SOC              : Integer;   // % carica
    ExpectedMileage  : Integer;   // km autonomia
    DumpEnergyKWh    : Double;    // kWh residui
    BatteryVoltage   : Double;    // V
    BatteryCurrent   : Double;    // A
    ChargeRemainTime : Integer;   // minuti alla fine ricarica
    ChargeSocSetting : Integer;   // limite ricarica %
    IsCharging       : Boolean;
    IsPlugged        : Boolean;
  end;

  // ---------------------------------------------------------------------------
  // Guida
  // ---------------------------------------------------------------------------
  TLPDriving = record
    TotalMileage: Integer;  // km totali
    Speed       : Integer;  // km/h
    GearStatus  : Integer;
    IsParked    : Boolean;
  end;

  // ---------------------------------------------------------------------------
  // Posizione GPS
  // ---------------------------------------------------------------------------
  TLPLocation = record
    Latitude   : Double;
    Longitude  : Double;
    PrivacyGPS : Integer;
  end;

  // ---------------------------------------------------------------------------
  // Clima
  // ---------------------------------------------------------------------------
  TLPClimate = record
    ACSwitch    : Boolean;
    ACSetting   : Double;   // temperatura impostata
    ACVolume    : Integer;
    OutdoorTemp : Integer;
    PTCState    : Integer;
  end;

  // ---------------------------------------------------------------------------
  // Porte e serrature
  // ---------------------------------------------------------------------------
  TLPDoors = record
    IsLocked         : Boolean;
    TrunkOpen        : Boolean;
    DriverDoorOpen   : Boolean;
    LeftRearDoorOpen : Boolean;
    RightRearDoorOpen: Boolean;
  end;

  // ---------------------------------------------------------------------------
  // Finestre
  // ---------------------------------------------------------------------------
  TLPWindows = record
    LeftFrontPercent : Integer;
    RightFrontPercent: Integer;
    LeftRearPercent  : Integer;
    RightRearPercent : Integer;
    SunShade         : Integer;
  end;

  // ---------------------------------------------------------------------------
  // Pressione gomme (kPa)
  // ---------------------------------------------------------------------------
  TLPTires = record
    FrontLeftKPa : Integer;
    FrontRightKPa: Integer;
    RearLeftKPa  : Integer;
    RearRightKPa : Integer;
    function FrontLeftBar: Double;
    function FrontRightBar: Double;
    function RearLeftBar: Double;
    function RearRightBar: Double;
    function AllOK: Boolean;
  end;

  // ---------------------------------------------------------------------------
  // Connettività
  // ---------------------------------------------------------------------------
  TLPConnectivity = record
    BluetoothState: Boolean;
    HotspotState  : Boolean;
    BluetoothAddr : string;
  end;

  // ---------------------------------------------------------------------------
  // Stato veicolo completo
  // ---------------------------------------------------------------------------
  TLPVehicleStatus = record
    Battery     : TLPBattery;
    Driving     : TLPDriving;
    Location    : TLPLocation;
    Climate     : TLPClimate;
    Doors       : TLPDoors;
    Windows     : TLPWindows;
    Tires       : TLPTires;
    Connectivity: TLPConnectivity;
    CollectTime : TDateTime;
    procedure Clear;
  end;

  // ---------------------------------------------------------------------------
  // Risposta generica API
  // ---------------------------------------------------------------------------
  TLPApiResponse = record
    Code    : Integer;
    Message : string;
    Success : Boolean;
    RawJSON : string;
    procedure Clear;
  end;

implementation

uses
  System.DateUtils;

{ TLPSession }

procedure TLPSession.Clear;
begin
  UserId := '';
  Token := '';
  SignIkm := '';
  SignSalt := '';
  SignInfo := '';
  RefreshToken := '';
  Base64Cert := '';
  AccountCertFile := '';
  AccountKeyFile := '';
end;

function TLPSession.IsAuthenticated: Boolean;
begin
  Result := (Token <> '') and (UserId <> '');
end;

{ TLPVehicle }

procedure TLPVehicle.Clear;
begin
  VIN := '';
  CarId := '';
  CarType := '';
  VehicleNickname := '';
  UserNickname := '';
  IsShared := False;
  Year := '';
end;

{ TLPTires }

function TLPTires.FrontLeftBar: Double;
begin
  Result := FrontLeftKPa / 100.0;
end;

function TLPTires.FrontRightBar: Double;
begin
  Result := FrontRightKPa / 100.0;
end;

function TLPTires.RearLeftBar: Double;
begin
  Result := RearLeftKPa / 100.0;
end;

function TLPTires.RearRightBar: Double;
begin
  Result := RearRightKPa / 100.0;
end;

function TLPTires.AllOK: Boolean;
begin
  // Pressione OK se tra 2.0 e 3.5 bar
  Result := (FrontLeftBar >= 2.0) and (FrontLeftBar <= 3.5) and
            (FrontRightBar >= 2.0) and (FrontRightBar <= 3.5) and
            (RearLeftBar >= 2.0) and (RearLeftBar <= 3.5) and
            (RearRightBar >= 2.0) and (RearRightBar <= 3.5);
end;

{ TLPVehicleStatus }

procedure TLPVehicleStatus.Clear;
begin
  FillChar(Self, SizeOf(Self), 0);
end;

{ TLPApiResponse }

procedure TLPApiResponse.Clear;
begin
  Code := -1;
  Message := '';
  Success := False;
  RawJSON := '';
end;

end.
