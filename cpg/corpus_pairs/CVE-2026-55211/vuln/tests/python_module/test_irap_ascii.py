import numpy as np
import pytest
import surfio


@pytest.mark.parametrize("func", [str, repr])
def test_irap_surface_string_representation(func):
    surface = surfio.IrapSurface(
        surfio.IrapHeader(ncol=3, nrow=2, xinc=2.0, yinc=2.0, xmax=2.0, ymax=2.0),
        values=np.zeros((3, 2)),
    )
    assert (
        func(surface)
        == "<IrapSurface(header=IrapHeader(ncol=3, nrow=2, xori=0, yori=0,"
        " xmax=2, ymax=2, xinc=2, yinc=2, rot=0, xrot=0, yrot=0), values=...)>"
    )


def test_reading_empty_file_errors(tmp_path):
    irap_path = tmp_path / "test.irap"
    irap_path.write_text("")
    with pytest.raises(RuntimeError, match="failed to map file"):
        surfio.IrapSurface.from_ascii_file(str(irap_path))


def test_reading_short_header_results_in_value_error():
    with pytest.raises(ValueError, match="Failed to read irap headers"):
        _ = surfio.IrapSurface.from_ascii_string("-996 1")


def test_reading_negative_dimensions_results_in_value_error():
    with pytest.raises(ValueError, match="Incorrect dimensions"):
        _ = surfio.IrapSurface.from_ascii_string(
            """\
            -996 -1 0.0 0.0
            0.0 0.0 0.0 0.0
            1 0.0 0.0 0.0
            0  0  0  0  0  0  0
            0.000000
            """
        )


def test_short_files_result_in_value_error():
    with pytest.raises(ValueError, match="End of file reached"):
        _ = surfio.IrapSurface.from_ascii_string(
            """\
                -996 5 0.0 0.0
                0.0 0.0 0.0 0.0
                5 0.0 0.0 0.0
                0  0  0  0  0  0  0
                0.000000
                """
        )


def test_non_floats_result_in_domain_error():
    with pytest.raises(ValueError, match="Failed to read values"):
        _ = surfio.IrapSurface.from_ascii_string(
            """\
            -996 5 0.0 0.0
            0.0 0.0 0.0 0.0
            5 0.0 0.0 0.0
            0  0  0  0  0  0  0
            not_a_number
            """
        )


def test_incorrect_header_types_result_in_value_error():
    with pytest.raises(ValueError, match="Failed to read irap headers"):
        _ = surfio.IrapSurface.from_ascii_string(
            """\
            -996 5 0.0 0.0
            0.0 0.0 0.0 0.0
            not_a_number 0.0 0.0 0.0
            0  0  0  0  0  0  0
            0.0
            """
        )


def test_reading_one_by_one_values():
    surface = surfio.IrapSurface.from_ascii_string(
        """\
        -996 1 2.0 3.0
        0.0 4.0 0.0 5.0
        1 0.0 0.0 0.0
        0  0  0  0  0  0  0
        1.000000
        """
    )
    assert surface.values.tolist() == [[1.0]]


def test_9999900_is_mapped_to_nan():
    surface = surfio.IrapSurface.from_ascii_string(
        """\
        -996 1 2.0 3.0
        0.0 4.0 0.0 5.0
        1 0.0 0.0 0.0
        0  0  0  0  0  0  0
        9999900.0000
        """
    )
    assert np.isnan(surface.values[0, 0])


def test_reading_no_leading_decimals():
    surface = surfio.IrapSurface.from_ascii_string(
        """\
        -996 1 2.0 3.0
        0.0 4.0 0.0 5.0
        1 0.0 0.0 0.0
        0  0  0  0  0  0  0
        .5"""
    )
    assert surface.values.tolist() == [[0.5]]


def test_reading_two_by_three_results_in_f_order_values():
    surface = surfio.IrapSurface.from_ascii_string(
        """\
        -996 2 2.0 2.0
        0.0 2.0 0.0 2.0
        3 0.0 0.0 0.0
        0  0  0  0  0  0  0
        1.000000 2.000000 3.000000
        4.000000 5.000000 6.000000
        """
    )
    assert surface.values.tolist() == [[1.0, 4.0], [2.0, 5.0], [3.0, 6.0]]


def test_reading_two_by_three_results_in_f_order_values_from_file(tmp_path):
    irap_path = tmp_path / "test.irap"
    irap_path.write_text(
        """\
        -996 2 2.0 2.0
        0.0 2.0 0.0 2.0
        3 0.0 0.0 0.0
        0  0  0  0  0  0  0
        1.000000 2.000000 3.000000
        4.000000 5.000000 6.000000
        """
    )
    surface = surfio.IrapSurface.from_ascii_file(str(irap_path))
    assert surface.values.tolist() == [[1.0, 4.0], [2.0, 5.0], [3.0, 6.0]]


def test_header_can_have_high_precision():
    # xtgeo can produce precision in the header
    # only possible with double precision
    surface = surfio.IrapSurface.from_ascii_string(
        """\
        -996 2 1.0 1.0
        0.0 1.0 2.610356564800451e-73 1.0
        2 0.0 0.0 2.610356564800451e-73
        0  0  0  0  0  0  0
        0.000000 0.000000 0.000000 0.000000
        """
    )
    assert surface.header.yrot == pytest.approx(2.6e-73, abs=1e-74)


def test_import_and_export_are_inverse():
    surface = surfio.IrapSurface(
        surfio.IrapHeader(ncol=3, nrow=2, xinc=2.0, yinc=2.0, xmax=4.0, ymax=2.0),
        values=np.arange(6, dtype=np.float32).reshape((3, 2)),
    )
    roundtrip = surfio.IrapSurface.from_ascii_string(surface.to_ascii_string())
    assert roundtrip.header == surface.header
    assert np.array_equal(roundtrip.values, surface.values)


def test_import_and_export_file_are_inverse(tmp_path):
    irap_path = tmp_path / "test.irap"
    surface = surfio.IrapSurface(
        surfio.IrapHeader(ncol=3, nrow=2, xinc=2.0, yinc=2.0, xmax=4.0, ymax=2.0),
        values=np.arange(6, dtype=np.float32).reshape((3, 2)),
    )
    surface.to_ascii_file(str(irap_path))
    roundtrip = surfio.IrapSurface.from_ascii_file(str(irap_path))
    assert roundtrip.header == surface.header
    assert np.array_equal(roundtrip.values, surface.values)


def test_exporting_nan_maps_to_9999900():
    surface = surfio.IrapSurface(
        surfio.IrapHeader(ncol=1, nrow=1, xinc=2.0, yinc=2.0, xmax=2.0, ymax=2.0),
        values=np.array([[np.nan]], dtype=np.float32),
    )

    assert "9999900.0000" in surface.to_ascii_string().split()[-1]


def test_exporting_produces_max_9_values_per_line():
    """
    This is the maximum supported by some applications
    """
    surface = surfio.IrapSurface(
        surfio.IrapHeader(ncol=10, nrow=1, xinc=2.0, yinc=2.0, xmax=2.0, ymax=2.0),
        values=np.zeros((10, 1), dtype=np.float32),
    )

    assert all(
        len(line.split()) <= 9 for line in surface.to_ascii_string().splitlines()
    )


def test_surfio_can_export_values_in_fortran_order():
    srf = surfio.IrapSurface(
        surfio.IrapHeader(ncol=3, nrow=4, xinc=1.0, yinc=1.0, xmax=2.0, ymax=3.0),
        values=np.asfortranarray(np.arange(12, dtype=np.float32).reshape((3, 4))),
    )
    buffer = srf.to_ascii_string()
    srf_imported = surfio.IrapSurface.from_ascii_string(buffer)

    assert np.allclose(srf.values, srf_imported.values)
    assert srf.header == srf_imported.header
