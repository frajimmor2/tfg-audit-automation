from reporterman.input_validations import (
        mode_validation,
        target_validation,
        ports_validation
        )
import typer
import pytest


def test_neg_mode_val():
    with pytest.raises(typer.BadParameter):
        mode_validation(5)


def test_pos_mod_val():
    assert mode_validation(1) == 1


# Those test doesn't return anything
def test_neg_target_validation():
    with pytest.raises(typer.BadParameter):
        target_validation("", 0)
        target_validation("", 1)
        target_validation("", 2)
        target_validation("192.1.1.2", 1)
        target_validation("10.10.10.10", 2)
        target_validation("192.1.1.1/23", 0)
        target_validation("10.0.0.3/19", 2)
        target_validation("12.12.12.12,12.12.12.15", 0)
        target_validation("10.10.10.10,10.10.10.11", 1)
        target_validation("100000.10000.122222.22222", 0)
        target_validation("10.10.10.10,10.10.10.10", 2)


def test_pos_target_validation():
    target_validation("34.34.34.34", 0)
    target_validation("10.0.0.3/19", 1)
    target_validation("12.12.12.12,12.12.12.11", 2)

    assert True


def test_neg_ports_validation():
    with pytest.raises(typer.BadParameter):
        ports_validation("")
        ports_validation("a")
        ports_validation("12,a")
        ports_validation("-12")
        ports_validation("264745728346")
        ports_validation("12,12,12,12")
        ports_validation("0")
        ports_validation("3,4,5,t,6")
        ports_validation("3,")


def test_pos_ports_validation():
    ports_validation("234")
    ports_validation("2,3,4,5")

    assert True
