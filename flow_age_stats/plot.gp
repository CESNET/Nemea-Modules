# Set the output terminal
set terminal png enhanced font "Arial,12"
set output "time_first.png"

# Set the title and axis labels
set title "TIME FIRST"
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
set xtics 10, 50  # Set x-axis tick marks at every 10th value, with minor ticks every 50th value

# Set the style for solid bars
set style fill solid 1.0

# Plot the data
plot "time_first.txt" using 1:3 with boxes lc rgb "#4daf4a" title "Flow Counts" axes x1y2, \
     "time_first.txt" using 1:2 with lines lc rgb "#e41a1c" title "Percentage" axes x1y1

set terminal png enhanced font "Arial,12"
set output "time_last.png"

# Set the title and axis labels
set title "TIME LAST"
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
set xtics 10, 50  # Set x-axis tick marks at every 10th value, with minor ticks every 50th value

# Set the style for solid bars
set style fill solid 1.0

# Plot the data
plot "time_last.txt" using 1:3 with boxes lc rgb "#4daf4a" title "Flow Counts" axes x1y2, \
     "time_last.txt" using 1:2 with lines lc rgb "#e41a1c" title "Percentage" axes x1y1