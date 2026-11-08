package ed25519group

import (
	"math/big"
	"testing"
)

func TestQL(t *testing.T) {
	qbytes := Q.Bytes()
	lbytes := L.Bytes()

	if len(qbytes) != 32 {
		t.Errorf("Expected Q to be 32 bytes integer but found to be: %d", len(qbytes))
	}

	if len(lbytes) != 32 {
		t.Errorf("Expected Q to be 32 bytes integer but found to be: %d", len(lbytes))
	}

	qExpected := "57896044618658097711785492504343953926634992332820282019728792003956564819949"
	lExpected := "7237005577332262213973186563042994240857116359379907606001950938285454250989"

	qText := Q.Text(10)
	lText := L.Text(10)
	if qText != qExpected {
		t.Errorf("Expected Q: %s\nFound Q: %s\n", qExpected, qText)
	}

	if lText != lExpected {
		t.Errorf("Expected L: %s\nFound L: %s\n", lExpected, lText)
	}

}

func TestD(t *testing.T) {
	dExpected := "-4513249062541557337682894930092624173785641285191125241628941591882900924598840740"
	dText := D.Text(10)

	if dText != dExpected {
		t.Errorf("Expected D: %s\nFound D: %s\n", dExpected, dText)
	}
}

func TestI(t *testing.T) {
	var iExpected big.Int
	iExpected.SetString("19681161376707505956807079304988542015446066515923890162744021073123829784752", 10)

	if I.Cmp(&iExpected) != 0 {
		t.Errorf("Calculated value of I is not same as expected value\nCalculated I: %s\n", I.Text(10))
	}
}

func TestBAndXrecover(t *testing.T) {
	var byExpected, bxExpected big.Int

	bxExpected.SetString("15112221349535400772501151409588531511454012693041857206046113283949847762202", 10)
	byExpected.SetString("46316835694926478169428394003475163141307993866256225615783033603165251855960", 10)

	if Bx.Cmp(&bxExpected) != 0 {
		t.Errorf("Calculated Bx and expected Bx are not same\nCalculated: %s\n", Bx.Text(10))
	}

	if By.Cmp(&byExpected) != 0 {
		t.Errorf("Calculated By and expected By are not same\nCalculated: %s\n", By.Text(10))
	}
}

func TestBAndBase(t *testing.T) {
	var affineX, affineY big.Int
	affineX.SetString("15112221349535400772501151409588531511454012693041857206046113283949847762202", 10)
	affineY.SetString("46316835694926478169428394003475163141307993866256225615783033603165251855960", 10)

	if B.X.Cmp(&affineX) != 0 {
		t.Errorf("Calculated base point X is not same as expected: %s", B.X.Text(10))
	}

	if B.Y.Cmp(&affineY) != 0 {
		t.Errorf("Calculated base point Y is not same as expected: %s", B.Y.Text(10))
	}

	var extendedX, extendedY, extendedT big.Int
	extendedZ := big.NewInt(1)

	extendedX.SetString("15112221349535400772501151409588531511454012693041857206046113283949847762202", 10)
	extendedY.SetString("46316835694926478169428394003475163141307993866256225615783033603165251855960", 10)
	extendedT.SetString("46827403850823179245072216630277197565144205554125654976674165829533817101731", 10)
	expectedExtended := ExtendedPoint{&extendedX, &extendedY, extendedZ, &extendedT}

	if expectedExtended.Cmp(&Base) != 0 {
		t.Errorf("Calculated base point is not same as the expected base point\n")
	}

	expectedZero := ExtendedPoint{big.NewInt(0), big.NewInt(1), big.NewInt(1), big.NewInt(0)}
	if expectedZero.Cmp(&Zero) != 0 {
		t.Errorf("Calculated extended Zero is not same as expected\n")
	}
}
