unit Utility;

interface
uses System.Math, System.SysUtils;

type
  TSoHResult = record
    Value: Double;        // SoH in %
    Reliable: Boolean;    // True se le condizioni di misura sono affidabili
    Reason: string;       // motivo se non affidabile (per debug/tooltip)
end;

// dichiarazioni
function CalibrateSpeed(ASpeed: Double): Double;
function CalcolaSoH(
  const ACapacitaKwh   : Double;
  const ACapNominale   : Double;
  const ASoc           : Double;
  const ATempCella     : Integer;
  const AChargeState   : Integer;
  const ACurrent       : Double
): TSoHResult;


implementation


function CalibrateSpeed(ASpeed: Double): Double;
const
  MinFactor = 1.04;   // scarto minimo  0 km/h
  MaxFactor = 1.064;  // scarto massimo  140 km/h
  MaxSpeed  = 140.0;  // max contaKM
var
  Factor: Double;
begin
  if ASpeed <= 0 then
    Exit(0);
  Factor := MinFactor + (MaxFactor - MinFactor) * (Min(ASpeed, MaxSpeed) / MaxSpeed);
  Result := ASpeed / Factor;
end;


function CalcolaSoH(
  const ACapacitaKwh   : Double;
  const ACapNominale   : Double;
  const ASoc           : Double;
  const ATempCella     : Integer;
  const AChargeState   : Integer;
  const ACurrent       : Double
): TSoHResult;
const
  SOC_MIN  = 30;
  SOC_MAX  = 70;
  TEMP_MIN = 15;
  TEMP_MAX = 30;
  CURR_MAX = 5.0;   // ampere
begin
  Result.Value    := 0;
  Result.Reliable := False;
  Result.Reason   := '';

  // --- verifica condizioni di affidabilità ---
  if ACapacitaKwh <= 0 then
  begin
    Result.Reason := 'capacità non calcolabile';
    Exit;
  end;

  if ACapNominale <= 0 then
  begin
    Result.Reason := 'capacità nominale non impostata';
    Exit;
  end;

  if (ASoc < SOC_MIN) or (ASoc > SOC_MAX) then
  begin
    Result.Reason := Format('SoC fuori range (%g%%, atteso %d-%d%%)',
                            [ASoc, SOC_MIN, SOC_MAX]);
    Exit;
  end;

  if (ATempCella < TEMP_MIN) or (ATempCella > TEMP_MAX) then
  begin
    Result.Reason := Format('temp cella fuori range (%d°C, atteso %d-%d°C)',
                            [ATempCella, TEMP_MIN, TEMP_MAX]);
    Exit;
  end;

  if AChargeState <> 0 then
  begin
    Result.Reason := 'in carica';
    Exit;
  end;

  if Abs(ACurrent) > CURR_MAX then
  begin
    Result.Reason := Format('corrente elevata (%.1f A)', [ACurrent]);
    Exit;
  end;

  // --- calcolo ---
  Result.Value := (ACapacitaKwh / ACapNominale) * 100.0;

  // Cap a 105% (pacco nuovo può lievemente superare nominale)
  if Result.Value > 105 then
    Result.Value := 105;

  Result.Reliable := True;
end;

end.
