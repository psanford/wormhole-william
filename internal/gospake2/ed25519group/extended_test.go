package ed25519group

import (
	"bytes"
	"math/big"
	"testing"
)

func TestCompress(t *testing.T) {
	affinePoint := NewAffinePoint("15112221349535400772501151409588531511454012693041857206046113283949847762202",
		"46316835694926478169428394003475163141307993866256225615783033603165251855960", 10)

	encoded := affinePoint.Compress()
	expected := []byte("Xfffffffffffffffffffffffffffffff")

	if !bytes.Equal(encoded, expected) {
		t.Errorf("Expected: %x\nGot: %x\n", expected, encoded)
	}
}

func TestDecompress(t *testing.T) {
	var bxExpected, by big.Int
	bxExpected.SetString("56797357330922913988458593931122727936228661521514257091994679493501599747208", 10)
	by.SetString("9865753461890859209229230381861602413891813861142323954581032314526085686034", 10)

	var affinePoint AffinePoint
	err := affinePoint.Decompress(by.Bytes())
	if err != nil {
		t.Errorf("Encountered while decompressing the point: %s", err.Error())
	}

	if affinePoint.X.Cmp(&bxExpected) != 0 {
		t.Errorf("Could not get the expected point: %s\n Found: %s\n", bxExpected.Text(10), affinePoint.X.Text(10))
	}
}

func TestToExtendedToAffine(t *testing.T) {
	affinePoint := NewAffinePoint("15112221349535400772501151409588531511454012693041857206046113283949847762202",
		"46316835694926478169428394003475163141307993866256225615783033603165251855960", 10)

	extendedPoint := affinePoint.ToExtended()

	var expectedX, expectedY, expectedT big.Int

	expectedX.SetString("15112221349535400772501151409588531511454012693041857206046113283949847762202", 10)
	expectedY.SetString("46316835694926478169428394003475163141307993866256225615783033603165251855960", 10)
	expectedT.SetString("46827403850823179245072216630277197565144205554125654976674165829533817101731", 10)

	if extendedPoint.X.Cmp(&expectedX) != 0 {
		t.Errorf("Calculated X is not same as expected X.\nCalculated: %s", extendedPoint.X.Text(10))
	}

	if extendedPoint.Y.Cmp(&expectedY) != 0 {
		t.Errorf("Calculated Y is not same as expected Y.\nCalculated: %s", extendedPoint.Y.Text(10))
	}

	if extendedPoint.Z.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("Calculated Z is not same as expected Z.\nCalculated: %s", extendedPoint.Z.Text(10))
	}

	if extendedPoint.T.Cmp(&expectedT) != 0 {
		t.Errorf("Calculated T is not same as expected T.\nCalculated: %s", extendedPoint.T.Text(10))
	}

	affinePoint2 := extendedPoint.ToAffine()
	if affinePoint2.X.Cmp(affinePoint.X) != 0 {
		t.Errorf("Expected affine X is not same as calculated affine X: %s\n", affinePoint2.X.Text(10))
	}

	if affinePoint2.Y.Cmp(affinePoint.Y) != 0 {
		t.Errorf("Expected affine Y is not same as calculated affine Y: %s\n", affinePoint2.Y.Text(10))
	}

}

func TestExtendedDouble(t *testing.T) {

	extended := NewExtendedPoint("15112221349535400772501151409588531511454012693041857206046113283949847762202",
		"46316835694926478169428394003475163141307993866256225615783033603165251855960", "1",
		"46827403850823179245072216630277197565144205554125654976674165829533817101731", 10)
	double := extended.Double()

	expectedDouble := NewExtendedPoint("22227142146053615383686711456592054533481723065238328079491086165754688571991",
		"23132612897935763947376118816302936961945753855592497212527330206034714001367",
		"47730969525411543486323345491594608200968822454103728746637676179095643807339",
		"10919983009863980608562433598283441687065789490543687699070727834902457043353", 10)

	if double.Cmp(&expectedDouble) != 0 {
		t.Errorf("Calculated doubled point is not same expected\n")
	}
}

func TestAddPoints(t *testing.T) {

	// Values got by doing e2 = Base.scalarmult(2) in python code and converted to affine form
	a := NewAffinePoint("24727413235106541002554574571675588834622768167397638456726423682521233608206",
		"15549675580280190176352668710449542251549572066445060580507079593062643049417", 10)

	// Values got by doing e3 = Base.scalarmult(3) in python code
	b := NewAffinePoint("46896733464454938657123544595386787789046198280132665686241321779790909858396",
		"8324843778533443976490377120369201138301417226297555316741202210403726505172", 10)

	// a23 = e2.add(e3)
	expected := NewAffinePoint("33467004535436536005251147249499675200073690106659565782908757308821616914995",
		"43097193783671926753355113395909008640284023746042808659097434958891230611693", 10)

	aExtended := a.ToExtended()
	bExtended := b.ToExtended()
	expectedExtended := expected.ToExtended()

	result := AddUnified(&aExtended, &bExtended)

	if result.Cmp(&expectedExtended) != 0 {
		t.Error("Result of addition is not as expected\n")
		t.Error("result.X: ", result.X.Text(10))
		t.Error("result.Y: ", result.Y.Text(10))
		t.Error("result.Z: ", result.Z.Text(10))
		t.Error("result.T: ", result.T.Text(10))
	}

	result2 := AddNonUnified(&aExtended, &bExtended)
	if result2.Cmp(&expectedExtended) != 0 {
		t.Error("Result of addition is not as expected\n")
		t.Error("result2.X: ", result2.X.Text(10))
		t.Error("result2.Y: ", result2.Y.Text(10))
		t.Error("result2.Z: ", result2.Z.Text(10))
		t.Error("result2.T: ", result2.T.Text(10))

	}
}

func TestScalarMult(t *testing.T) {
	expectedE2 := NewExtendedPoint("31572838575331059057342163797972886727660149484699688009146539496252481216713",
		"41339707479937298439316536954371931555983632843580664771033057417136410949558",
		"27971462590048802052051123461091430939310997843358111001019517386392356661549",
		"43121190281288673492401570074446923025908728083539052033074561131891108202500", 10)
	e2 := Base.ScalarMultSlow(big.NewInt(2))

	if e2.Cmp(&expectedE2) != 0 {
		t.Errorf("Calculated Base.scalarmult(2) is not same as expected\n")
	}

	e2Fast := Base.ScalarMultFast(big.NewInt(2))
	if e2Fast.Cmp(&expectedE2) != 0 {
		t.Errorf("Calculated Base.scalarmult(2) is not same as expected\n")
	}

	i := new(big.Int)
	i.SetString("5933653109026664864021724363388722168120056719345989670116987585247831633119", 10)

	expectedBi := NewExtendedPoint("52663549417893902378822438348607947279268249586335037669450125759987032599148",
		"8544822497306704236208517720441583972005251623834745162898315189678700682817",
		"14899434427685041794317036647067246221968587291971540298912736948046159697704",
		"53097516746831583386726361190615146000659836635091723348442275566728750840194", 10)

	bi := Base.ScalarMultFast(i)
	if bi.Cmp(&expectedBi) != 0 {
		t.Errorf("Calculated Base.scalarmult(i) is not as expected\n")
	}

	expectedE2i := NewExtendedPoint("10034741768686632130980546085207022274246583252274825135558990199435925953112",
		"31872117241245196036527699968161133664124544005124577790248383210087079162403",
		"3464634589557859084159692542752514398868396799662357798408685988658275479260",
		"51926223521728482433272281465230554628235849880538432566357514268180279749569", 10)
	e2i := e2.ScalarMultSlow(i)
	if e2i.Cmp(&expectedE2i) != 0 {
		t.Errorf("Calculated e2.scalarmult(i) is not as expected\n")
	}

	zero := Base.ScalarMultSlow(big.NewInt(0))
	if zero.Cmp(&Zero) != 0 {
		t.Errorf("Was expecting identity element as answer for multiplying point with 0\n")
	}

	same := Base.ScalarMultSlow(big.NewInt(1))
	if Base.Cmp(&same) != 0 {
		t.Errorf("Was expecting point back on multiplying by 1\n")
	}

	zeroF := Base.ScalarMultFast(big.NewInt(0))
	if zeroF.Cmp(&Zero) != 0 {
		t.Errorf("Was expecting identity element as answer for multiplying point with 0\n")
	}

	sameF := Base.ScalarMultFast(big.NewInt(1))
	if Base.Cmp(&sameF) != 0 {
		t.Errorf("Was expecting point back on multiplying by 1\n")
	}

	biF := Base.ScalarMultFast(i)
	if biF.Cmp(&expectedBi) != 0 {
		t.Errorf("Calculated Base.scalarmultfast(i) is not as expected\n")
	}

}

func testNotOnCurve(t *testing.T) {
	// i =
	// 4556846509855858358510207695914328712911211177702565036567836100763640591393
	// t.to_bytes(32, 'little')
	ibytes := []byte("b'!\xf46\xc7\x8e\xfaY\xa8301\xbc_y\x06\xb3{\x15){\xa4\xf4\x11R\xd2\x8a]\x05o\x15\x13\n'")
	affine := AffinePoint{}
	err := affine.Decompress(ibytes)
	if err == nil {
		t.Errorf("Execpted not on curve error. But point decoded")
	}
}
