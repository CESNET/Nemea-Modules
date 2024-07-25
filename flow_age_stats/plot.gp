# Check if we have the right number of arguments
if (ARGC != 3) {
    print "Error: Two data files and a title suffix are required."
    print "Usage: gnuplot -c plot.gp time_first.txt time_last.txt title_suffix"
    exit
}

# Store the file names and title suffix in variables
time_first_file = ARG1
time_last_file = ARG2
title_suffix = ARG3

# Set the output terminal for the first graph
set terminal png enhanced font "Arial,12"
set output sprintf("time_first_%s.png", title_suffix)

# Set the title and axis labels
set title sprintf("TIME FIRST %s", title_suffix)
set xlabel "Age (s)"
set ylabel "Percentage (%)"
set y2label "Number of Flows"

# Set the axis ranges
set xrange [1:600]
set yrange [0:*]
set y2range [0:*]

# Set the tics and grid
set ytics nomirror
set y2tics nomirror
set grid
set xtics 10, 50

# Set the style for solid bars
set style fill solid 1.0

# Plot the data for the first graph
plot time_first_file using 1:3 with boxes lc rgb "#4daf4a" title "Flow Counts" axes x1y2, \
     time_first_file using 1:2 with lines lc rgb "#e41a1c" title "Percentage" axes x1y1

# Set the output terminal for the second graph
set terminal png enhanced font "Arial,12"
set output sprintf("time_last_%s.png", title_suffix)

# Set the title and axis labels
set title sprintf("TIME LAST %s", title_suffix)
set xlabel "Age (s)"
set ylabel "Percentage (%)"
set y2label "Number of Flows"

# Set the axis ranges
set xrange [1:600]
set yrange [0:*]
set y2range [0:*]

# Set the tics and grid
set ytics nomirror
set y2tics nomirror
set grid
set xtics 10, 50

# Set the style for solid bars
set style fill solid 1.0

# Plot the data for the second graph
plot time_last_file using 1:3 with boxes lc rgb "#4daf4a" title "Flow Counts" axes x1y2, \
     time_last_file using 1:2 with lines lc rgb "#e41a1c" title "Percentage" axes x1y1