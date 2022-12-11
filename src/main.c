#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/cpumask.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>

#include <linux/mm.h>
#include <linux/pgtable.h>

#include <linux/slab.h>     // for kmalloc, kfree

#define PROC_NAME "hw2"
#define MAX_CPU_NUMS 40
#define PERIOD_DEFAULT = 5;

MODULE_AUTHOR("Kim, Minhyup");
MODULE_LICENSE("GPL v2");


// int period = PERIOD_DEFAULT;
// module_param(period, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
// MODULE_PARM_DESC(period, "Period for investigate");


void traverseAll(struct seq_file* s);
void printBaseInfo(struct seq_file* s, struct task_struct* currProcess);
void printf_bar(struct seq_file* s);
void printf_code(struct seq_file* s, struct task_struct* currProcess);
void printf_data(struct seq_file* s, struct task_struct* currProcess);
void printf_heap(struct seq_file* s, struct task_struct* currProcess);
void printf_stack(struct seq_file* s, struct task_struct* currProcess);

static unsigned long vaddr2paddr(struct seq_file* s, struct task_struct* currProcess, unsigned long vaddr);
/**
 * This function is called for each "step" of a sequence
 *
 */
static int hw2_seq_show(struct seq_file *s, void *v)
{
    traverseAll(s);


    loff_t *spos = (loff_t*) v;
    return 0;
}

#define next_task(p) \
        list_entry_rcu((p)->tasks.next, struct task_struct, tasks)

#define for_each_process(p) \
        for (p = &init_task ; (p = next_task(p)) != &init_task ; )

static void get_pgtable_macro(struct seq_file* s)
{
    seq_printf(s, "PAGE_OFFSET = 0x%lx\n", PAGE_OFFSET);
    seq_printf(s,"PGDIR_SHIFT = %d\n", PGDIR_SHIFT);
    seq_printf(s,"PUD_SHIFT = %d\n", PUD_SHIFT);
    seq_printf(s,"PMD_SHIFT = %d\n", PMD_SHIFT);
    seq_printf(s,"PAGE_SHIFT = %d\n", PAGE_SHIFT);

    seq_printf(s,"PTRS_PER_PGD = %d\n", PTRS_PER_PGD);
    seq_printf(s,"PTRS_PER_PUD = %d\n", PTRS_PER_PUD);
    seq_printf(s,"PTRS_PER_PMD = %d\n", PTRS_PER_PMD);
    seq_printf(s,"PTRS_PER_PTE = %d\n", PTRS_PER_PTE);

    seq_printf(s,"PAGE_MASK = 0x%lx\n", PAGE_MASK);
}

void printBaseInfo(struct seq_file* s, struct task_struct* currProcess){

    printf_bar(s);
    seq_printf(s, "Student name(ID): %s(%s)\n", "Kim, Minhyup", "2017127046");
    seq_printf(s, "Process name(ID): %s(%lu)\n", currProcess->comm, currProcess->pid);
    seq_printf(s, "Memory info #%d\n", 0); // 0은 조사한 횟수
    seq_printf(s, "PGD base address: 0x%lx\n", currProcess->mm->pgd);

    printf_code(s, currProcess);
    printf_data(s, currProcess);
    printf_heap(s, currProcess);
    printf_stack(s, currProcess);
    

    // vaddr2paddr(s, a->mm->start_code);

}

static unsigned long vaddr2paddr(struct seq_file* s, struct task_struct* currProcess, unsigned long vaddr)
{
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    unsigned long paddr = 0;
    unsigned long page_addr = 0;
    unsigned long page_offset = 0;

    pgd = pgd_offset(currProcess->mm, vaddr);
    seq_printf(s, "- PGD address, value: 0x%lx, 0x%lx\n", pgd, pgd_val(*pgd));

    pud = pud_offset((p4d_t*) pgd, vaddr);
    seq_printf(s, "- PUD address, value: 0x%lx, 0x%lx\n", pud, pud_val(*pud));

    pmd = pmd_offset(pud, vaddr);
    seq_printf(s, "- PMD address, value: 0x%lx, 0x%lx\n", pmd, pmd_val(*pmd));


    pte = pte_offset_kernel(pmd, vaddr);
    seq_printf(s, "- PTE address, value: 0x%lx, 0x%lx\n", pte, pte_val(*pte));


    /* Page frame physical address mechanism | offset */
    page_addr = pte_val(*pte) & PAGE_MASK;
    page_offset = vaddr & ~PAGE_MASK;
    paddr = page_addr | page_offset;
     
    seq_printf(s, "- Physical addrewss: 0x%lx\n", paddr);

    // seq_printf(s, "page_addr = %lx, page_offset = %lx\n", page_addr, page_offset);
    // seq_printf(s, "vaddr = %lx, paddr = %lx\n", vaddr, paddr);

    return paddr;
}

void traverseAll(struct seq_file* s){
    struct task_struct* task;
    
    rcu_read_lock();
    for_each_process(task)
    {
        if (task->policy == SCHED_NORMAL){
            // printBaseInfo(s, task);
            seq_printf(s, "pid = %d, comm = %s\n", task->pid, task->comm);
        }
    }
    rcu_read_unlock();
}

void printf_bar(struct seq_file* s){
    int i;
    for (i = 0; i < 80; i++) seq_printf(s, "-");
    seq_printf(s, "\n");
}

void printf_code(struct seq_file* s, struct task_struct* currProcess){
    printf_bar(s);
    seq_printf(s, "Code Area Start\n");

    
    // Virtual Addr
    seq_printf(s, "- Virtual address: 0x%lx\n", currProcess->mm->start_code);
    vaddr2paddr(s, currProcess, currProcess->mm->start_code);
    printf_bar(s);
    
    seq_printf(s, "Code Area End\n");
}

void printf_data(struct seq_file* s, struct task_struct* currProcess){
    printf_bar(s);
    seq_printf(s, "Data Area Start\n");
    
    // Virtual Addr
    seq_printf(s, "- Virtual address: 0x%lx\n", currProcess->mm->start_data);
    vaddr2paddr(s, currProcess, currProcess->mm->start_data);
    printf_bar(s);
    
    seq_printf(s, "Data Area End\n");
}

void printf_heap(struct seq_file* s, struct task_struct* currProcess){
    printf_bar(s);
    seq_printf(s, "Heap Area Start\n");
    
    // Virtual Addr
    seq_printf(s, "- Virtual address: 0x%lx\n", currProcess->mm->start_brk);
    vaddr2paddr(s, currProcess, currProcess->mm->start_brk);
    printf_bar(s);
    
    seq_printf(s, "Heap Area End\n");
}

void printf_stack(struct seq_file* s, struct task_struct* currProcess){
    printf_bar(s);
    seq_printf(s, "Stack Area Start\n");

    // Virtual Addr
    seq_printf(s, "- Virtual address: 0x%lx\n", currProcess->mm->start_stack);
    vaddr2paddr(s, currProcess, currProcess->mm->start_stack);
    printf_bar(s);
    
    seq_printf(s, "Stack Area End\n");
}


/**
 * This function is called at the beginning of a sequence.
 * ie, when:
 * − the /proc file is read (first time)
 * − after the function stop (end of sequence)
 *
 */
static void *hw2_seq_start(struct seq_file *s, loff_t *pos)
{
    static unsigned long counter = 0;
    /* beginning a new sequence ? */
    if (*pos == 0)
    {
        /* yes => return a non null value to begin the sequence */
        return &counter;
    }
    else
    {
        /* no => it's the end of the sequence, return end to stop reading */
        *pos = 0;
        return NULL;
    }
}

/**
 * This function is called after the beginning of a sequence.
 * It's called untill the return is NULL (this ends the sequence).
 *
 */
static void *hw2_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
    unsigned long *tmp_v = (unsigned long *)v;
    (*tmp_v)++;
    (*pos)++;
    return NULL;
}

/**
 * This function is called at the end of a sequence
 *
 */
static void hw2_seq_stop(struct seq_file *s, void *v)
{
    /* nothing to do, we use a static value in start() */
}


static struct seq_operations hw2_seq_ops = {
    .start = hw2_seq_start,
    .next = hw2_seq_next,
    .stop = hw2_seq_stop,
    .show = hw2_seq_show
};

static int hw2_proc_open(struct inode *inode, struct file *file) {
    return seq_open(file, &hw2_seq_ops);
}

static const struct proc_ops hw2_proc_fops = {
	.proc_open = hw2_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = seq_release
};

static int __init hw2_init(void) {
    struct proc_dir_entry *proc_file_entry;
    proc_file_entry = proc_create(PROC_NAME, 0, NULL, &hw2_proc_fops);

	return 0; 
}

static void __exit hw2_exit(void) {
    remove_proc_entry(PROC_NAME, NULL);
}

module_init(hw2_init);
module_exit(hw2_exit);