"""
Script de Treinamento com Fine-Tuning LoRA (PEFT) para Especialista em SOC L3.
Modelo Base: Qwen/Qwen2.5-0.5B-Instruct
Autor: Projeto FineTuning-SOC-Ollama
"""

import os
import sys
import json
import torch

# Garantir codificação UTF-8 no Windows para emojis e logs
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass
from datasets import load_dataset
from transformers import (
    AutoTokenizer,
    AutoModelForCausalLM,
    TrainingArguments,
    Trainer,
    DataCollatorForSeq2Seq,
    TrainerCallback
)
from peft import (
    LoraConfig,
    get_peft_model,
    TaskType,
    PeftModel
)

# 1. Configurações Globais e Hiperparâmetros
MODEL_ID = "Qwen/Qwen2.5-0.5B-Instruct"
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
OUTPUT_DIR = os.path.join(BASE_DIR, "models", "lora_soc_adapter")
MERGED_DIR = os.path.join(BASE_DIR, "models", "soc_analyst_merged")
METRICS_PATH = os.path.join(BASE_DIR, "training", "loss_history.json")

TRAIN_FILE = os.path.join(DATA_DIR, "soc_train.jsonl")
TEST_FILE = os.path.join(DATA_DIR, "soc_test.jsonl")

# Callback customizado para registrar a curva de Loss a cada etapa para visualização no Streamlit
class LossHistoryCallback(TrainerCallback):
    def __init__(self, output_file):
        self.output_file = output_file
        self.history = []

    def on_log(self, args, state, control, logs=None, **kwargs):
        if logs is not None:
            entry = {
                "step": state.global_step,
                "epoch": round(state.epoch, 2) if state.epoch is not None else 0,
                "loss": logs.get("loss"),
                "eval_loss": logs.get("eval_loss"),
                "learning_rate": logs.get("learning_rate")
            }
            # Filtrar entradas válidas com loss
            if entry["loss"] is not None or entry["eval_loss"] is not None:
                self.history.append(entry)
                # Salva em tempo real no disco
                with open(self.output_file, "w", encoding="utf-8") as f:
                    json.dump(self.history, f, indent=2)

def prepare_data(tokenizer):
    """Carrega os datasets em formato ChatML e aplica a tokenização supervisionada."""
    dataset = load_dataset(
        "json",
        data_files={"train": TRAIN_FILE, "test": TEST_FILE}
    )

    def tokenize_function(example):
        # Utiliza o template nativo de Chat do Qwen2.5
        conversation = example["messages"]
        prompt = tokenizer.apply_chat_template(
            conversation,
            tokenize=False,
            add_generation_prompt=False
        )
        
        tokenized = tokenizer(
            prompt,
            truncation=True,
            max_length=512,
            padding=False
        )
        # Em Causal LM, labels são idênticos aos input_ids (auto-regressivo)
        tokenized["labels"] = tokenized["input_ids"].copy()
        return tokenized

    tokenized_dataset = dataset.map(
        tokenize_function,
        remove_columns=dataset["train"].column_names,
        desc="Tokenizando datasets"
    )
    return tokenized_dataset

def main():
    print("=" * 60)
    print("🚀 Iniciando Treinamento LoRA - Especialista SOC L3")
    print(f"📦 Modelo Base: {MODEL_ID}")
    print(f"📂 Diretório de Saída: {OUTPUT_DIR}")
    print("=" * 60)

    # 2. Carregar Tokenizer
    print("\n[1/5] Carregando Tokenizer...")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID, use_fast=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    # 3. Carregar Datasets
    print("\n[2/5] Carregando e Tokenizando dados...")
    tokenized_data = prepare_data(tokenizer)
    print(f"✔ Amostras de Treino: {len(tokenized_data['train'])}")
    print(f"✔ Amostras de Validação: {len(tokenized_data['test'])}")

    # 4. Carregar Modelo Base
    print("\n[3/5] Carregando Modelo Base...")
    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"⚙️ Dispositivo de Execução: {device.upper()}")

    model = AutoModelForCausalLM.from_pretrained(
        MODEL_ID,
        torch_dtype=torch.float32 if device == "cpu" else torch.bfloat16,
        low_cpu_mem_usage=True
    )

    # 5. Configurar LoRA (Low-Rank Adaptation)
    print("\n[4/5] Injetando Adaptadores LoRA...")
    lora_config = LoraConfig(
        r=16,                           # Posto da matriz (rank)
        lora_alpha=32,                  # Fator de escala alfa
        target_modules=["q_proj", "v_proj", "k_proj", "o_proj"], # Projeções de atenção
        lora_dropout=0.05,              # Regularização contra overfitting
        bias="none",
        task_type=TaskType.CAUSAL_LM
    )
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()

    # 6. Hiperparâmetros de Treinamento
    training_args = TrainingArguments(
        output_dir=os.path.join(BASE_DIR, "training", "checkpoints"),
        num_train_epochs=3,
        per_device_train_batch_size=2,
        per_device_eval_batch_size=2,
        gradient_accumulation_steps=4,  # Efetivo batch_size = 8
        learning_rate=2e-4,
        warmup_steps=3,
        weight_decay=0.01,
        logging_steps=2,
        eval_strategy="steps",
        eval_steps=5,
        save_strategy="steps",
        save_steps=10,
        save_total_limit=1,
        report_to="none",
        fp16=False,                     # Otimizado para estabilidade em CPU
        use_cpu=(device == "cpu")
    )

    loss_callback = LossHistoryCallback(METRICS_PATH)

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=tokenized_data["train"],
        eval_dataset=tokenized_data["test"],
        data_collator=DataCollatorForSeq2Seq(tokenizer, pad_to_multiple_of=8, return_tensors="pt"),
        callbacks=[loss_callback]
    )

    # 7. Executar Treinamento
    print("\n[5/5] Iniciando Ciclo de Treinamento...")
    train_result = trainer.train()

    print("\n" + "=" * 60)
    print("✅ Treinamento Concluído com Sucesso!")
    print(f"Perda Final (Loss): {train_result.training_loss:.4f}")
    print("=" * 60)

    # Salvar Adaptador LoRA e Tokenizer
    print(f"\n💾 Salvando pesos LoRA em: {OUTPUT_DIR}")
    model.save_pretrained(OUTPUT_DIR)
    tokenizer.save_pretrained(OUTPUT_DIR)

    # 8. Opcional: Mesclar pesos LoRA com modelo base para exportação direta
    print(f"\n🔗 Criando versão mesclada (Merged Model) em: {MERGED_DIR}...")
    try:
        merged_model = model.merge_and_unload()
        merged_model.save_pretrained(MERGED_DIR)
        tokenizer.save_pretrained(MERGED_DIR)
        print("✔ Modelo mesclado com sucesso!")
    except Exception as e:
        print(f"⚠️ Aviso ao mesclar modelo: {e}")

    print(f"\n📈 Histórico de Loss salvo em: {METRICS_PATH}")
    print("Pronto para a Etapa 3 (Deploy no Ollama via Modelfile)!")

if __name__ == "__main__":
    main()
