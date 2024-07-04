import numpy as np

# Load the variable from the dataset
def load_variable():
    matriks = [[4100000, 3, 33528, 3, 21, 6500000],
            [4100000, 4, 37305, 4, 20, 6500000],
            [2900000, 3, 44125, 3, 18, 6300000],
            [4100000, 4, 30887, 5, 21, 6100000],
            [3300000, 3, 30892, 4, 20, 6000000],
            [3000000, 3, 31200, 3, 20, 5900000],
            [2200000, 2, 31688, 3, 18, 5500000],
            [2100000, 2, 33794, 3, 21, 5000000],
            [6250000, 5, 30617, 5, 30, 8000000],
            [4160000, 5, 44338, 5, 25, 7600000],
            [2500000, 3, 37279, 3, 18, 6600000],
            [2500000, 3, 36511, 3, 17, 6400000]]
    return matriks

def name_alternatives():
    return ['Near UNS & ISI (Jebres)',
            'Near Moewardi Hospital (Jebres),',
            'Near Gede Market (Jebres)',
            'Near Balapan Station & Sheikh Zayed Mosque (Banjarsari, Jebres)',
            'Near Manahan Stadium (Banjarsari)',
            'Near Legi Market (Banjarsari)',
            'Near Klewer Market, Keraton Surakarta, & Alun-alun (Pasar Kliwon)',
            'Near Notoharjo Market (Pasar Kliwon)',
            'Near Solo Grand Mall (Laweyan)',
            'Near Solo Square Mall (Laweyan)',
            'In Jl. Veteran (Serengan)',
            'In Jl. Radjiman (Laweyan, Serengan)']

def name_criteria():
    return ['Building Rental Price', 'Accessibility', 'Location Crowd', 'Safety', 'Number of Competitors', 'Budget']

# Define the variable information
def variable_info():
    return ['Cost', 'Benefit', 'Benefit', 'Benefit', 'Cost', 'Cost']

# Normalize the matrix
def get_normalize(matrix):
    # Create a new matrix to store normalized values
    normalized_matrix = np.zeros_like(matrix, dtype=float)
    
    for i in range(len(matrix[0])):  # for each column
        norm = 0
        for j in range(len(matrix)):  # for each row in the column
            norm += matrix[j][i] ** 2
        norm = norm ** 0.5
        
        if norm == 0:
            continue  # Avoid division by zero
        
        for j in range(len(matrix)):  # normalize each element in the column
            normalized_matrix[j][i] = matrix[j][i] / norm

    return normalized_matrix

# Get the fuzzy scale
def get_fuzzy_scale(value):
    if value == 0:
        return [0, 0, 0.25]
    elif value == 1:
        return [0, 0.25, 0.5]
    elif value == 2:
        return [0.25, 0.5, 0.75]
    elif value == 3:
        return [0.5, 0.75, 1.0]
    else:
        return [0.75, 1.0, 1.0]

# Build the decision matrix criteria
def build_dm_criteria(values, total_dm):
    # Create a new matrix to store the fuzzy scale values
    dm_criteria = np.zeros((total_dm, 6, 3))

    # Get the fuzzy scale for each value
    for i in range(total_dm):
        for j in range(6):
            dm_criteria[i][j] = get_fuzzy_scale(values[i][j])

    return dm_criteria

# Build the aggregate decision matrix criteria
def build_aggregate_dm_criteria(dm_criteria):
    aggregated_criteria = np.zeros((6, 3))

    # Get the average of the fuzzy scale values
    for i in range(6):
        for j in range(3):
            aggregated_criteria[i][j] = np.average(dm_criteria[:, i, j])
    
    return aggregated_criteria

# Weighted normalized matrix
def weighted_normalized_matrix(normalized_matrix, aggregated_criteria):
    weighted_normalized_matrix = np.zeros((12, 6, 3))

    # Multiply the normalized matrix with the aggregated criteria
    for i in range(12):
        for j in range(6):
            for k in range(3):
                weighted_normalized_matrix[i][j][k] = normalized_matrix[i][j] * aggregated_criteria[j][k]

    return weighted_normalized_matrix

# Get the FPIS and FNIS
def get_fpis_fnis(weighted_normalized_matrix, matrix_info):
    fpis = np.zeros((6, 3))
    fnis = np.zeros((6, 3))

    # Get the FPIS and FNIS values
    for i in range(6):
        for j in range(3):
            if matrix_info[i] == 'Cost':
                fpis[i][j] = min([weighted_normalized_matrix[k][i][j] for k in range(12)])
                fnis[i][j] = max([weighted_normalized_matrix[k][i][j] for k in range(12)])
            else:
                fpis[i][j] = max([weighted_normalized_matrix[k][i][j] for k in range(12)])
                fnis[i][j] = min([weighted_normalized_matrix[k][i][j] for k in range(12)])

    return fpis, fnis

# Get the distance from FPIS and FNIS
def get_distance_from_fpis_fnis(weighted_normalized_matrix, fpis, fnis):
    distance_fpis = np.zeros((12, 6))
    distance_fnis = np.zeros((12, 6))

    # Calculate the distance from FPIS and FNIS
    for i in range(12):
        for j in range(6):
            distance_fpis[i][j] = sum([(weighted_normalized_matrix[i][j][k] - fpis[j][k]) ** 2 for k in range(3)]) ** 0.5
            distance_fnis[i][j] = sum([(weighted_normalized_matrix[i][j][k] - fnis[j][k]) ** 2 for k in range(3)]) ** 0.5

    return distance_fpis, distance_fnis

# Get the closest distance
def get_closest_distance(distance_fpis, distance_fnis):
    closest_distance = np.zeros(12)

    # Calculate the closest distance
    for i in range(12):
        fnis = 0
        fpis = 0
        for j in range(6):
            fnis += distance_fnis[i][j]
            fpis += distance_fpis[i][j]

        # print(fnis, fpis)
        closest_distance[i] = fnis / (fnis + fpis)

    return closest_distance

# Check if the script is run as the main program
if __name__ == "__main__":
    matrix = load_variable()
    matrix_info = variable_info()
    # print('matriks original: ', matrix)

    normalized_matrix = get_normalize(matrix)
    print('\nmatriks normalized: ', normalized_matrix)

    values_dm = [[3,	2,	4,	1,	1,	2],
                [2,	1,	3,	2,	2,	3],
                [2,	3,	2,	1,	1,	2]]
    
    dm_criteria = build_dm_criteria(values_dm, 3)
    print('\nmatriks dm criteria: ', dm_criteria)

    aggregated_criteria = build_aggregate_dm_criteria(dm_criteria)
    print('\nmatriks aggregated criteria: ', aggregated_criteria)

    weighted_normalized_matriks = weighted_normalized_matrix(normalized_matrix, aggregated_criteria)
    print('\nmatriks weighted normalized: ', weighted_normalized_matriks)

    fpis, fnis = get_fpis_fnis(weighted_normalized_matriks, matrix_info)
    print('\nmatriks fpis: ', fpis)
    print('\nmatriks fnis: ', fnis)

    distance_fpis, distance_fnis = get_distance_from_fpis_fnis(weighted_normalized_matriks, fpis, fnis)
    print('\nmatriks distance fpis: ', distance_fpis)
    print('\nmatriks distance fnis: ', distance_fnis)

    closest_distance = get_closest_distance(distance_fpis, distance_fnis)
    print('\nmatriks closest distance: ', closest_distance)

    name_alternatives = name_alternatives()

    sorted_alternatives = sorted(range(len(closest_distance)), key=lambda k: closest_distance[k], reverse=True)
    for i in range(12):
        print(name_alternatives[sorted_alternatives[i]], closest_distance[sorted_alternatives[i]])